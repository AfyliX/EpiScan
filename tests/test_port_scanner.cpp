#include <gtest/gtest.h>
#include "network/PortScanner.hpp"

// These tests use localhost — port 22 (SSH) may or may not be open.
// We only test that the scanner returns valid results without crashing.

TEST(PortScanner, ScanLocalhostDoesNotCrash)
{
    // Scan a very narrow range on localhost
    const auto results = episcan::network::scanPorts("127.0.0.1",
                                                      {1, 10},
                                                      {500, 4, false});
    // Results can be empty (all closed) — that's fine
    for (const auto &r : results) {
        EXPECT_EQ(r.state, episcan::network::PortState::Open);
        EXPECT_EQ(r.protocol, "tcp");
        EXPECT_GE(r.port, static_cast<uint16_t>(1));
        EXPECT_LE(r.port, static_cast<uint16_t>(10));
    }
}

TEST(PortScanner, ScanPortListDoesNotCrash)
{
    const std::vector<uint16_t> ports = {22, 80, 443, 8080};
    const auto results = episcan::network::scanPortList("127.0.0.1", ports, {500, 4, false});
    for (const auto &r : results) {
        EXPECT_EQ(r.state, episcan::network::PortState::Open);
    }
}

TEST(PortScanner, ScanInvalidHostReturnsEmpty)
{
    const auto results = episcan::network::scanPorts("invalid.host.does.not.exist.local",
                                                      {80, 80}, {200, 2, false});
    EXPECT_TRUE(results.empty());
}

TEST(PortScanner, ScanLocalhostPort22)
{
    // If SSH is running, port 22 should show open; otherwise empty — both valid
    const auto results = episcan::network::scanPortList("127.0.0.1", {22}, {1000, 1, false});
    // Just verify no crash and result is sensible
    EXPECT_LE(results.size(), 1u);
}

TEST(PortScanner, ScanIPv6LoopbackDoesNotCrash)
{
    // getaddrinfo(AF_UNSPEC) resolves "::1" to an IPv6 sockaddr, exercising the
    // IPv6 path of tryConnect() (#75). No CIDR enumeration: an IPv6 prefix has
    // up to 2^96 addresses, so subnet scanning isn't implemented — only single
    // IPv6 hosts are supported, same as a literal IPv4 host.
    const auto results = episcan::network::scanPorts("::1", {1, 20}, {500, 4, false});
    for (const auto &r : results) {
        EXPECT_EQ(r.state, episcan::network::PortState::Open);
        EXPECT_GE(r.port, static_cast<uint16_t>(1));
        EXPECT_LE(r.port, static_cast<uint16_t>(20));
    }
}
