#include "network/PortScanner.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

namespace episcan {
namespace network {
namespace {

namespace asio = boost::asio;

// One fresh io_context per attempt keeps the worker-thread-pool structure
// below unchanged (each thread blocks on a single port at a time) while the
// connect+timeout itself is done through Boost.Asio (#71) instead of raw
// POSIX sockets. The resolver has no protocol hint, so it returns both IPv4
// and IPv6 endpoints when available (dual-stack, like getaddrinfo(AF_UNSPEC)
// did) and async_connect tries them in order until one succeeds (#75).
bool tryConnect(const std::string &host, uint16_t port, int timeoutMs)
{
    asio::io_context io;

    asio::ip::tcp::resolver resolver(io);
    boost::system::error_code resolveEc;
    const auto endpoints = resolver.resolve(host, std::to_string(port), resolveEc);
    if (resolveEc || endpoints.empty()) {
        return false;
    }

    asio::ip::tcp::socket socket(io);
    asio::steady_timer    timer(io);

    bool                       connectDone = false;
    boost::system::error_code connectEc   = asio::error::would_block;

    timer.expires_after(std::chrono::milliseconds(timeoutMs));
    timer.async_wait([&](const boost::system::error_code &ec) {
        if (!ec) {
            boost::system::error_code ignore;
            socket.cancel(ignore);
        }
    });

    asio::async_connect(socket, endpoints,
        [&](const boost::system::error_code &ec, const asio::ip::tcp::endpoint &) {
            connectEc   = ec;
            connectDone = true;
            timer.cancel();
        });

    io.run();

    return connectDone && !connectEc;
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
