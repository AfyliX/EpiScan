#include "network/BannerGrabber.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <regex>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

namespace episcan {
namespace network {
namespace {

// Probes HTTP pour forcer les banners sur les serveurs web
static const std::string k_httpProbe = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";
static const std::string k_ftpProbe  = "";   // FTP envoie le banner spontanément
static const std::string k_smtpProbe = "";   // SMTP envoie le banner spontanément
static const std::string k_sshProbe  = "";   // SSH envoie le banner spontanément

struct ServiceProbe {
    uint16_t    port;
    std::string probe;
};

static const std::vector<ServiceProbe> k_probes = {
    { 21,  k_ftpProbe  },
    { 22,  k_sshProbe  },
    { 25,  k_smtpProbe },
    { 80,  k_httpProbe },
    { 110, "" },
    { 143, "" },
    { 443, k_httpProbe },
    { 465, "" },
    { 587, "" },
    { 993, "" },
    { 995, "" },
    { 3306, "" },
    { 5432, "" },
    { 6379, "" },
    { 8080, k_httpProbe },
    { 8443, k_httpProbe },
};

struct ServiceSignature {
    std::string pattern;
    std::string service;
    std::regex  versionRegex;
};

static const std::vector<ServiceSignature> k_signatures = {
    { "SSH-",         "ssh",    std::regex(R"(SSH-[\d.]+-([\w._-]+))")     },
    { "220 ",         "ftp",    std::regex(R"(220[- ]([\w._\-/ ]+))")      },
    { "SMTP",         "smtp",   std::regex(R"(220[- ]([\w._\-/ ]+))")      },
    { "HTTP/",        "http",   std::regex(R"(Server:\s*([\w._\-/ ]+)\r)") },
    { "MySQL",        "mysql",  std::regex(R"(([\d.]+)-(?:MySQL|MariaDB))") },
    { "PostgreSQL",   "postgresql", std::regex(R"(PostgreSQL\s+([\d.]+))")  },
    { "+OK ",         "pop3",   std::regex(R"(\+OK\s+([\w._\-/ ]+))")      },
    { "* OK ",        "imap",   std::regex(R"(\* OK\s+([\w._\-/ ]+))")     },
    { "-ERR",         "redis",  std::regex(R"(redis_version:([\d.]+))")     },
};

std::string detectService(const std::string &banner, std::string &version)
{
    for (const auto &sig : k_signatures) {
        if (banner.find(sig.pattern) != std::string::npos) {
            std::smatch m;
            if (std::regex_search(banner, m, sig.versionRegex) && m.size() > 1) {
                version = m[1].str();
                // Trim trailing whitespace
                while (!version.empty() && (version.back() == '\r' || version.back() == '\n'
                                         || version.back() == ' ')) {
                    version.pop_back();
                }
            }
            return sig.service;
        }
    }
    return "";
}

int resolveAndConnect(const std::string &host, uint16_t port, int timeoutMs)
{
    addrinfo hints = {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *res = nullptr;
    const std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
        return -1;
    }

    int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    // Set send/recv timeouts
    struct timeval tv;
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        ::close(fd);
        return -1;
    }

    freeaddrinfo(res);
    return fd;
}

} // namespace

BannerResult grabBanner(const std::string &host, uint16_t port, int timeoutMs)
{
    BannerResult result;

    int fd = resolveAndConnect(host, port, timeoutMs);
    if (fd < 0) return result;

    // Send probe if we know one for this port
    for (const auto &p : k_probes) {
        if (p.port == port && !p.probe.empty()) {
            ::send(fd, p.probe.c_str(), p.probe.size(), MSG_NOSIGNAL);
            break;
        }
    }

    // Read banner (up to 4KB)
    char buf[4096] = {};
    const ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
    ::close(fd);

    if (n <= 0) return result;

    result.banner  = std::string(buf, static_cast<std::size_t>(n));
    result.grabbed = true;
    result.service = detectService(result.banner, result.version);

    // Truncate to first 512 printable chars for display
    if (result.banner.size() > 512) result.banner.resize(512);

    return result;
}

} // namespace network
} // namespace episcan
