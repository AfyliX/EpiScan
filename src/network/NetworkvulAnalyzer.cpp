#include "network/NetworkvulAnalyzer.hpp"
#include "network/PortScanner.hpp"
#include "network/ServiceDetector.hpp"
#include "network/CveLookup.hpp"
#include "core/Severity.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

#ifdef EPISCAN_HAVE_OPENSSL
#  include <openssl/ssl.h>
#  include <openssl/x509.h>
#  include <openssl/err.h>
#  include <netdb.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  include <arpa/inet.h>
#endif

namespace episcan {
namespace network {
namespace {

// ── SSL/TLS Audit (#74) ───────────────────────────────────────────────────────

#ifdef EPISCAN_HAVE_OPENSSL

static int tcpConnect(const std::string &host, uint16_t port, int timeoutMs)
{
    addrinfo hints = {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res)
        return -1;
    int fd = ::socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    struct timeval tv { timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res); ::close(fd); return -1;
    }
    freeaddrinfo(res);
    return fd;
}

std::vector<Vulnerability> auditSsl(const std::string &host, uint16_t port,
                                     int timeoutMs)
{
    std::vector<Vulnerability> findings;

    // ── Test TLS 1.0 ──────────────────────────────────────────────────────────
    auto testProto = [&](int minVer, int maxVer, const std::string &label,
                         const std::string &cve, const std::string &remediation)
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return;
        SSL_CTX_set_min_proto_version(ctx, minVer);
        SSL_CTX_set_max_proto_version(ctx, maxVer);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

        int fd = tcpConnect(host, port, timeoutMs);
        if (fd < 0) { SSL_CTX_free(ctx); return; }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, host.c_str());

        if (SSL_connect(ssl) == 1) {
            // Protocol accepted by server — flagged
            Vulnerability v;
            v.id          = "ssl-" + label;
            v.file        = host + ":" + std::to_string(port);
            v.line        = 0;
            v.severity    = Severity::High;
            v.message     = "Protocole " + label + " déprécié accepté par le serveur";
            v.cwe         = "CWE-326";
            v.remediation = remediation;
            v.cvssScore   = 7.5;
            v.category    = "ssl";
            if (!cve.empty()) v.id += "-" + cve;
            findings.push_back(std::move(v));
        }

        SSL_free(ssl);
        ::close(fd);
        SSL_CTX_free(ctx);
    };

#  if defined(TLS1_VERSION)
    testProto(TLS1_VERSION,   TLS1_VERSION,   "TLSv1.0",
              "", "Désactiver TLS 1.0/1.1; utiliser TLS 1.2+ uniquement");
#  endif
#  if defined(TLS1_1_VERSION)
    testProto(TLS1_1_VERSION, TLS1_1_VERSION, "TLSv1.1",
              "", "Désactiver TLS 1.1; utiliser TLS 1.2+ uniquement");
#  endif

    // ── Certificate checks ────────────────────────────────────────────────────
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

        int fd = tcpConnect(host, port, timeoutMs);
        if (fd >= 0) {
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
            SSL_set_tlsext_host_name(ssl, host.c_str());

            if (SSL_connect(ssl) == 1) {
                X509 *cert = SSL_get_peer_certificate(ssl);
                if (cert) {
                    // Check expiry
                    const ASN1_TIME *notAfter = X509_get0_notAfter(cert);
                    if (X509_cmp_current_time(notAfter) < 0) {
                        Vulnerability v;
                        v.id          = "ssl-cert-expired";
                        v.file        = host + ":" + std::to_string(port);
                        v.severity    = Severity::High;
                        v.message     = "Certificat SSL/TLS expiré";
                        v.cwe         = "CWE-298";
                        v.remediation = "Renouveler le certificat TLS";
                        v.cvssScore   = 7.0;
                        v.category    = "ssl";
                        findings.push_back(std::move(v));
                    }

                    // Check self-signed (issuer == subject)
                    if (X509_NAME_cmp(X509_get_issuer_name(cert),
                                      X509_get_subject_name(cert)) == 0) {
                        Vulnerability v;
                        v.id          = "ssl-self-signed";
                        v.file        = host + ":" + std::to_string(port);
                        v.severity    = Severity::Medium;
                        v.message     = "Certificat SSL auto-signé";
                        v.cwe         = "CWE-295";
                        v.remediation = "Utiliser un certificat signé par une CA de confiance (Let's Encrypt)";
                        v.cvssScore   = 5.5;
                        v.category    = "ssl";
                        findings.push_back(std::move(v));
                    }

                    X509_free(cert);
                }
            }
            SSL_free(ssl);
            ::close(fd);
        }
        SSL_CTX_free(ctx);
    }

    // ── Weak cipher + missing HSTS header ────────────────────────────────────
    // Note: explicit SSLv2/SSLv3 probing and a raw Heartbleed protocol-level probe
    // are intentionally not implemented — modern OpenSSL (3.x) removed SSLv2/SSLv3
    // client support entirely, so they can no longer be negotiated to test for, and
    // a from-scratch Heartbleed packet probe only matters against decade-old OpenSSL
    // builds (1.0.1–1.0.1f) — the version-signature check above already flags those.
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

        int fd = tcpConnect(host, port, timeoutMs);
        if (fd >= 0) {
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
            SSL_set_tlsext_host_name(ssl, host.c_str());

            if (SSL_connect(ssl) == 1) {
                const char *cipherName = SSL_get_cipher_name(ssl);
                if (cipherName) {
                    std::string lowered(cipherName);
                    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

                    static const std::vector<std::string> weakMarkers = {
                        "rc4", "des", "3des", "null", "export", "md5", "anon"
                    };
                    for (const auto &marker : weakMarkers) {
                        if (lowered.find(marker) == std::string::npos) continue;
                        Vulnerability v;
                        v.id          = "ssl-weak-cipher";
                        v.file        = host + ":" + std::to_string(port);
                        v.severity    = Severity::High;
                        v.message     = "Chiffrement faible négocié par le serveur : " + std::string(cipherName);
                        v.cwe         = "CWE-327";
                        v.remediation = "Désactiver RC4/DES/3DES/NULL/EXPORT/MD5; n'autoriser que des suites AEAD modernes (AES-GCM, ChaCha20-Poly1305)";
                        v.cvssScore   = 7.4;
                        v.category    = "ssl";
                        findings.push_back(std::move(v));
                        break;
                    }
                }

                const std::string request = "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
                if (SSL_write(ssl, request.data(), static_cast<int>(request.size())) > 0) {
                    char buffer[4096] = {};
                    const int bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                    if (bytesRead > 0) {
                        std::string response(buffer, static_cast<std::size_t>(bytesRead));
                        std::transform(response.begin(), response.end(), response.begin(),
                            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

                        if (response.find("strict-transport-security") == std::string::npos) {
                            Vulnerability v;
                            v.id          = "ssl-missing-hsts";
                            v.file        = host + ":" + std::to_string(port);
                            v.severity    = Severity::Medium;
                            v.message     = "En-tête HTTP Strict-Transport-Security (HSTS) absent";
                            v.cwe         = "CWE-319";
                            v.remediation = "Ajouter l'en-tête Strict-Transport-Security: max-age=31536000; includeSubDomains";
                            v.cvssScore   = 4.8;
                            v.category    = "ssl";
                            findings.push_back(std::move(v));
                        }
                    }
                }
            }
            SSL_free(ssl);
            ::close(fd);
        }
        SSL_CTX_free(ctx);
    }

    return findings;
}

#endif // EPISCAN_HAVE_OPENSSL

// ── Offline known-vulnerable version signatures (#73, no NVD network call) ──
// Small local table of historically backdoored/critical software versions,
// matched against the banner text. Intentionally offline: no NVD API calls,
// no rate limits, works air-gapped. See docs/benchmark.md for the rationale.

struct VersionSignature {
    std::string bannerNeedle; // case-insensitive substring to match in the banner
    std::string id;
    std::string cve;
    Severity    severity;
    double      cvss;
    std::string message;
    std::string remediation;
};

const std::vector<VersionSignature> &knownVulnerableVersions()
{
    static const std::vector<VersionSignature> sigs = {
        {"vsftpd 2.3.4", "vsftpd-backdoor", "CVE-2011-2523", Severity::Critical, 10.0,
         "vsftpd 2.3.4 — version trojanisée avec backdoor connue (smiley face backdoor)",
         "Mettre à jour vsftpd immédiatement vers une version non compromise"},
        {"proftpd 1.3.3c", "proftpd-backdoor", "CVE-2010-4221", Severity::Critical, 9.8,
         "ProFTPD 1.3.3c — version compromise avec backdoor connue",
         "Mettre à jour ProFTPD vers une version récente"},
        {"unrealircd 3.2.8.1", "unrealircd-backdoor", "CVE-2010-2075", Severity::Critical, 10.0,
         "UnrealIRCd 3.2.8.1 — version trojanisée avec backdoor connue",
         "Remplacer immédiatement par une version officielle non modifiée"},
        {"samba 3.5", "samba-cve-2017-7494", "CVE-2017-7494", Severity::Critical, 9.8,
         "Samba 3.5.x — vulnérable à SambaCry (exécution de code à distance)",
         "Mettre à jour Samba vers une version patchée (>= 4.6.4 / 4.5.10 / 4.4.14)"},
        {"exim 4.91", "exim-cve-2019-10149", "CVE-2019-10149", Severity::Critical, 9.8,
         "Exim < 4.92 — vulnérable à l'exécution de code à distance (\"Return of the WIZard\")",
         "Mettre à jour Exim vers 4.92 ou plus récent"},
        {"openssl/1.0.1", "openssl-heartbleed", "CVE-2014-0160", Severity::Critical, 9.4,
         "OpenSSL 1.0.1 (pré-1.0.1g) — potentiellement vulnérable à Heartbleed",
         "Mettre à jour OpenSSL vers 1.0.1g ou plus récent et régénérer les certificats/clés"},
        {"apache/2.2", "apache-2.2-eol", "", Severity::Medium, 5.3,
         "Apache httpd 2.2.x — branche en fin de vie, ne reçoit plus de correctifs de sécurité",
         "Migrer vers Apache httpd 2.4.x maintenu"},
        {"openssh-4.", "openssh-legacy", "", Severity::High, 7.5,
         "OpenSSH 4.x — version très ancienne avec plusieurs CVE connues non corrigées",
         "Mettre à jour OpenSSH vers une version récente maintenue"},
    };
    return sigs;
}

void checkVersionSignatures(const std::vector<ServiceInfo> &services,
                             const std::string              &host,
                             std::vector<Vulnerability>      &findings)
{
    for (const auto &svc : services) {
        if (svc.banner.empty() && svc.version.empty()) continue;
        std::string haystack = svc.banner + " " + svc.version;
        std::transform(haystack.begin(), haystack.end(), haystack.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        for (const auto &sig : knownVulnerableVersions()) {
            if (haystack.find(sig.bannerNeedle) == std::string::npos) continue;

            Vulnerability v;
            v.id          = "network-" + sig.id;
            v.file        = host + ":" + std::to_string(svc.port);
            v.severity    = sig.severity;
            v.message     = sig.message;
            v.cwe         = "CWE-1104"; // Use of Unmaintained Third Party Components
            v.remediation = sig.remediation;
            v.cvssScore   = sig.cvss;
            v.category    = "network";
            if (!sig.cve.empty()) v.id += "-" + sig.cve;
            findings.push_back(std::move(v));
        }
    }
}

// ── Service vulnerability patterns (#72 integration) ─────────────────────────

std::vector<Vulnerability> checkServiceVulns(const std::vector<ServiceInfo> &services,
                                              const std::string              &host)
{
    std::vector<Vulnerability> findings;
    checkVersionSignatures(services, host, findings);

    for (const auto &svc : services) {
        // Telnet — cleartext
        if (svc.port == 23 || svc.service == "telnet") {
            Vulnerability v;
            v.id          = "network-telnet";
            v.file        = host + ":" + std::to_string(svc.port);
            v.severity    = Severity::High;
            v.message     = "Telnet actif — protocole en clair, remplacer par SSH";
            v.cwe         = "CWE-319";
            v.remediation = "Désactiver Telnet et utiliser SSH 2.0";
            v.cvssScore   = 8.0;
            v.category    = "network";
            findings.push_back(std::move(v));
        }

        // FTP — cleartext
        if (svc.port == 21 || svc.service == "ftp") {
            Vulnerability v;
            v.id          = "network-ftp-cleartext";
            v.file        = host + ":" + std::to_string(svc.port);
            v.severity    = Severity::Medium;
            v.message     = "FTP actif — identifiants transmis en clair";
            v.cwe         = "CWE-319";
            v.remediation = "Utiliser SFTP (SSH) ou FTPS à la place de FTP";
            v.cvssScore   = 6.5;
            v.category    = "network";
            findings.push_back(std::move(v));
        }

        // Redis sans auth
        if (svc.port == 6379 || svc.service == "redis") {
            Vulnerability v;
            v.id          = "network-redis-exposed";
            v.file        = host + ":" + std::to_string(svc.port);
            v.severity    = Severity::Critical;
            v.message     = "Redis exposé sur le réseau — risque d'accès non authentifié";
            v.cwe         = "CWE-306";
            v.remediation = "Configurer requirepass; lier Redis à 127.0.0.1 uniquement";
            v.cvssScore   = 9.8;
            v.category    = "network";
            findings.push_back(std::move(v));
        }

        // MongoDB sans auth
        if (svc.port == 27017 || svc.service == "mongodb") {
            Vulnerability v;
            v.id          = "network-mongodb-exposed";
            v.file        = host + ":" + std::to_string(svc.port);
            v.severity    = Severity::Critical;
            v.message     = "MongoDB exposé sur le réseau — vérifier l'authentification";
            v.cwe         = "CWE-306";
            v.remediation = "Activer l'authentification MongoDB; restreindre l'accès réseau";
            v.cvssScore   = 9.8;
            v.category    = "network";
            findings.push_back(std::move(v));
        }

        // RDP exposed
        if (svc.port == 3389 || svc.service == "rdp") {
            Vulnerability v;
            v.id          = "network-rdp-exposed";
            v.file        = host + ":" + std::to_string(svc.port);
            v.severity    = Severity::High;
            v.message     = "RDP exposé sur Internet — cible privilégiée pour attaques brute-force";
            v.cwe         = "CWE-307";
            v.remediation = "Désactiver RDP ou le protéger via VPN + NLA obligatoire";
            v.cvssScore   = 8.5;
            v.category    = "network";
            findings.push_back(std::move(v));
        }
    }

    return findings;
}

} // namespace

NetworkScanResult analyzeNetwork(const NetworkScanOptions &opts)
{
    NetworkScanResult result;

    // 1. Port scan
    network::ScanConfig portCfg;
    portCfg.timeoutMs = opts.timeoutMs;
    const auto openPorts = scanPorts(opts.target, {opts.portStart, opts.portEnd}, portCfg);
    result.scannedPorts = static_cast<std::size_t>(opts.portEnd - opts.portStart + 1);

    // 2. Service detection + banner grabbing
    std::vector<uint16_t> openPortNums;
    openPortNums.reserve(openPorts.size());
    for (const auto &pr : openPorts) openPortNums.push_back(pr.port);

    result.services = detectServices(opts.target, openPortNums, opts.timeoutMs);

    // 3. Service vulnerability checks
    auto svcFindings = checkServiceVulns(result.services, opts.target);
    result.findings.insert(result.findings.end(), svcFindings.begin(), svcFindings.end());

    // 4. SSL/TLS audit (#74)
#ifdef EPISCAN_HAVE_OPENSSL
    if (opts.sslAudit) {
        for (const auto &svc : result.services) {
            const bool isSslPort = svc.port == 443 || svc.port == 8443
                                || svc.port == 465 || svc.port == 993
                                || svc.port == 995 || svc.port == 636;
            if (isSslPort || svc.service == "https" || svc.service == "https-alt") {
                auto sslFindings = auditSsl(opts.target, svc.port, opts.timeoutMs);
                result.findings.insert(result.findings.end(), sslFindings.begin(), sslFindings.end());
            }
        }
    }
#endif

    // 5. Live NVD CVE lookup (#73) — opt-in, offline signature table above
    // already covers the common case without a network dependency.
    if (opts.cveCheck) {
        for (const auto &svc : result.services) {
            auto cveFindings = lookupNvdCves(svc, opts.target);
            result.findings.insert(result.findings.end(), cveFindings.begin(), cveFindings.end());
        }
    }

    return result;
}

} // namespace network
} // namespace episcan
