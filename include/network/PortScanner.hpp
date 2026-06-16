#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace episcan {
namespace network {

enum class PortState { Open, Closed, Filtered };

struct PortResult {
    uint16_t  port     = 0;
    PortState state    = PortState::Filtered;
    std::string protocol; // "tcp" | "udp"
};

struct PortRange {
    uint16_t start = 1;
    uint16_t end   = 1024;
};

struct ScanConfig {
    int         timeoutMs   = 2000;
    std::size_t threads     = 0;   // 0 = hw_concurrency * 2
    bool        udpEnabled  = false;
};

// Scanne les ports TCP (et UDP si activé) d'une cible
std::vector<PortResult> scanPorts(const std::string &target,
                                   PortRange          range = {1, 1024},
                                   ScanConfig         cfg   = {});

// Variante : liste de ports spécifiques
std::vector<PortResult> scanPortList(const std::string          &target,
                                      const std::vector<uint16_t> &ports,
                                      ScanConfig                   cfg = {});

} // namespace network
} // namespace episcan
