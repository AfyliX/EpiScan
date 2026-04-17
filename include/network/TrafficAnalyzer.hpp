#pragma once

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace episcan {
namespace network {

// ── A single suspicious packet finding ──────────────────────────────────────

struct PacketFinding {
    std::string    ruleId;
    std::string    srcIp;
    std::string    dstIp;
    uint16_t       srcPort        = 0;
    uint16_t       dstPort        = 0;
    std::string    protocol;          // "TCP" | "UDP" | "OTHER"
    std::string    severity;          // "critical" | "high" | "medium" | "low"
    std::string    description;
    std::string    payloadSnippet;    // first ~80 printable chars of payload
    std::time_t    timestamp       = 0;
};

// ── Options passed to analyzeTraffic() ──────────────────────────────────────

struct TrafficScanOptions {
    std::string            interface       = "any";   // live capture interface
    std::string            pcapFile;                  // if non-empty: read .pcap file
    int                    durationSeconds = 30;      // live capture duration (0 = until maxPackets)
    int                    maxPackets      = 0;       // 0 = unlimited
    std::filesystem::path  reportPath;                // JSON output (empty = no file)
};

// ── Progress callback: (packetsSeen, findingsSoFar) ─────────────────────────

using TrafficCallback = std::function<void(std::size_t packetsSeen,
                                           std::size_t findingsSoFar)>;

// ── Public API ───────────────────────────────────────────────────────────────

/// Capture and analyse network traffic.
/// Requires CAP_NET_RAW (or root) for live capture; pcap file needs no privilege.
std::vector<PacketFinding> analyzeTraffic(const TrafficScanOptions &opts,
                                          const TrafficCallback    &cb = {});

/// Write findings to a JSON report file.
void writeTrafficReport(const std::filesystem::path        &path,
                        const std::vector<PacketFinding>   &findings);

/// Return available network interfaces (names only).
std::vector<std::string> listInterfaces();

} // namespace network
} // namespace episcan
