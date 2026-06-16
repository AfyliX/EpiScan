#pragma once
#include "ServiceDetector.hpp"
#include "core/Vulnerability.hpp"
#include <string>
#include <vector>

namespace episcan {
namespace network {

struct NetworkScanOptions {
    std::string target;
    uint16_t    portStart    = 1;
    uint16_t    portEnd      = 1024;
    int         timeoutMs    = 2000;
    bool        sslAudit     = true;
    bool        cveCheck     = false; // requires network access
};

struct NetworkScanResult {
    std::vector<ServiceInfo>    services;
    std::vector<Vulnerability>  findings;
    std::size_t                 scannedPorts = 0;
};

// Scanne réseau complet : ports + banners + audit SSL + détection vulns
NetworkScanResult analyzeNetwork(const NetworkScanOptions &opts);

} // namespace network
} // namespace episcan
