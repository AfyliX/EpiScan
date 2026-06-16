#include "network/ServiceDetector.hpp"

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace episcan {
namespace network {
namespace {

const std::unordered_map<uint16_t, std::string> &wellKnownPorts()
{
    static const std::unordered_map<uint16_t, std::string> table = {
        {21,   "ftp"},
        {22,   "ssh"},
        {23,   "telnet"},
        {25,   "smtp"},
        {53,   "dns"},
        {80,   "http"},
        {110,  "pop3"},
        {143,  "imap"},
        {443,  "https"},
        {465,  "smtps"},
        {587,  "submission"},
        {636,  "ldaps"},
        {993,  "imaps"},
        {995,  "pop3s"},
        {1433, "mssql"},
        {3306, "mysql"},
        {3389, "rdp"},
        {5432, "postgresql"},
        {5900, "vnc"},
        {6379, "redis"},
        {8080, "http-alt"},
        {8443, "https-alt"},
        {9200, "elasticsearch"},
        {27017,"mongodb"},
    };
    return table;
}

} // namespace

std::string wellKnownService(uint16_t port)
{
    const auto &table = wellKnownPorts();
    const auto it = table.find(port);
    return it != table.end() ? it->second : "";
}

std::vector<ServiceInfo> detectServices(const std::string          &host,
                                         const std::vector<uint16_t> &openPorts,
                                         int                          timeoutMs)
{
    std::vector<ServiceInfo> infos;
    infos.reserve(openPorts.size());

    for (const uint16_t port : openPorts) {
        ServiceInfo si;
        si.port    = port;
        si.service = wellKnownService(port);

        // Try banner grab for richer detection
        const auto banner = grabBanner(host, port, timeoutMs);
        if (banner.grabbed) {
            si.banner  = banner.banner;
            if (!banner.service.empty()) si.service = banner.service;
            si.version = banner.version;
        }

        infos.push_back(std::move(si));
    }

    return infos;
}

} // namespace network
} // namespace episcan
