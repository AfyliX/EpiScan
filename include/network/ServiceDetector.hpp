#pragma once
#include "BannerGrabber.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace episcan {
namespace network {

struct ServiceInfo {
    uint16_t    port    = 0;
    std::string service;
    std::string version;
    std::string banner;
};

// Identifie les services sur les ports ouverts
std::vector<ServiceInfo> detectServices(const std::string          &host,
                                         const std::vector<uint16_t> &openPorts,
                                         int                          timeoutMs = 3000);

// Nom de service well-known depuis le numéro de port
std::string wellKnownService(uint16_t port);

} // namespace network
} // namespace episcan
