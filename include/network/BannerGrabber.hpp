#pragma once
#include <cstdint>
#include <string>

namespace episcan {
namespace network {

struct BannerResult {
    std::string banner;
    std::string service;   // détecté depuis le banner
    std::string version;   // extrait du banner
    bool        grabbed = false;
};

// Connexion TCP, lecture du banner initial
BannerResult grabBanner(const std::string &host, uint16_t port, int timeoutMs = 3000);

} // namespace network
} // namespace episcan
