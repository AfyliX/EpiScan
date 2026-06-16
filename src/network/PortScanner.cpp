#include "network/PortScanner.hpp"

#include <arpa/inet.h>
#include <atomic>
#include <fcntl.h>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace episcan {
namespace network {
namespace {

bool tryConnect(const std::string &host, uint16_t port, int timeoutMs)
{
    addrinfo hints = {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *res = nullptr;
    const std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
        return false;
    }

    int fd = ::socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return false; }

    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    ::connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);

    struct timeval tv;
    tv.tv_sec  = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    const int sel = select(fd + 1, nullptr, &wset, nullptr, &tv);
    bool open = false;
    if (sel > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        open = (err == 0);
    }

    ::close(fd);
    return open;
}

std::size_t defaultThreadCount(const ScanConfig &cfg)
{
    if (cfg.threads > 0) return cfg.threads;
    const unsigned int hw = std::thread::hardware_concurrency();
    return (hw == 0 ? 2 : hw) * 2;
}

} // namespace

std::vector<PortResult> scanPorts(const std::string &target,
                                   PortRange          range,
                                   ScanConfig         cfg)
{
    std::vector<uint16_t> ports;
    ports.reserve(range.end - range.start + 1);
    for (uint16_t p = range.start; p <= range.end; ++p) {
        ports.push_back(p);
    }
    return scanPortList(target, ports, cfg);
}

std::vector<PortResult> scanPortList(const std::string          &target,
                                      const std::vector<uint16_t> &ports,
                                      ScanConfig                   cfg)
{
    std::vector<PortResult>   results(ports.size());
    std::atomic<std::size_t>  nextIdx{0};
    const std::size_t         threadCount = defaultThreadCount(cfg);

    // Initialize results
    for (std::size_t i = 0; i < ports.size(); ++i) {
        results[i].port     = ports[i];
        results[i].protocol = "tcp";
        results[i].state    = PortState::Filtered;
    }

    std::vector<std::thread> workers;
    workers.reserve(threadCount);

    for (std::size_t t = 0; t < threadCount; ++t) {
        workers.emplace_back([&]() {
            while (true) {
                const std::size_t idx = nextIdx.fetch_add(1);
                if (idx >= ports.size()) break;
                const uint16_t port = ports[idx];
                const bool open = tryConnect(target, port, cfg.timeoutMs);
                results[idx].state = open ? PortState::Open : PortState::Closed;
            }
        });
    }

    for (auto &w : workers) w.join();

    // Filter: keep only open ports for the caller's convenience
    std::vector<PortResult> open;
    for (const auto &r : results) {
        if (r.state == PortState::Open) open.push_back(r);
    }
    return open;
}

} // namespace network
} // namespace episcan
