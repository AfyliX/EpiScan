#include "network/NetworkvulAnalyzer.hpp"
#include "network/PortScanner.hpp"
#include "network/ServiceDetector.hpp"
#include "core/Severity.hpp"

#include <algorithm>
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

    return findings;
}

#endif // EPISCAN_HAVE_OPENSSL

// ── Service vulnerability patterns (#72 integration) ─────────────────────────

std::vector<Vulnerability> checkServiceVulns(const std::vector<ServiceInfo> &services,
                                              const std::string              &host)
{
    std::vector<Vulnerability> findings;

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

    return result;
}

} // namespace network
} // namespace episcan
