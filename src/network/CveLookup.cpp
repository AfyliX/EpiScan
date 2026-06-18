#include "network/CveLookup.hpp"
#include "core/Severity.hpp"

#include <nlohmann/json.hpp>

#ifdef EPISCAN_HAVE_CURL
#include <curl/curl.h>
#endif

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <thread>

namespace episcan {
namespace network {
namespace {

// ── Known product patterns → CPE vendor:product ──────────────────────────────
// Best-effort regex guess, not a real CPE dictionary lookup (see header note).

struct CpeProductPattern {
    std::regex  bannerPattern; // must capture the version in group 1
    std::string vendor;
    std::string product;
};

const std::vector<CpeProductPattern> &cpeProductPatterns()
{
    static const std::vector<CpeProductPattern> patterns = {
        {std::regex(R"(Apache/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex::icase), "apache", "http_server"},
        {std::regex(R"(nginx/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex::icase), "nginx", "nginx"},
        {std::regex(R"(OpenSSH[_/]?\s*([0-9]+\.[0-9]+(?:p[0-9]+)?))", std::regex::icase), "openbsd", "openssh"},
        {std::regex(R"(vsftpd\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex::icase), "vsftpd_project", "vsftpd"},
        {std::regex(R"(ProFTPD\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex::icase), "proftpd", "proftpd"},
        {std::regex(R"(MySQL\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex::icase), "mysql", "mysql"},
        {std::regex(R"(PostgreSQL\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex::icase), "postgresql", "postgresql"},
        {std::regex(R"(Postfix\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex::icase), "postfix", "postfix"},
        {std::regex(R"(Exim\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex::icase), "exim", "exim"},
        {std::regex(R"(Dovecot\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex::icase), "dovecot", "dovecot"},
        {std::regex(R"(PHP/?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?))", std::regex::icase), "php", "php"},
    };
    return patterns;
}

std::filesystem::path cacheFilePath()
{
    const char *xdgCache = std::getenv("XDG_CACHE_HOME");
    std::filesystem::path base;
    if (xdgCache && *xdgCache) {
        base = std::filesystem::path(xdgCache);
    } else if (const char *home = std::getenv("HOME")) {
        base = std::filesystem::path(home) / ".cache";
    } else {
        base = std::filesystem::temp_directory_path();
    }
    return base / "episcan" / "nvd_cache.json";
}

constexpr long k_cacheMaxAgeSeconds = 7 * 24 * 3600; // 7 days

std::mutex g_nvdMutex; // serializes live requests across threads for rate limiting
std::chrono::steady_clock::time_point g_lastRequest{};
constexpr std::chrono::seconds k_minRequestInterval{7}; // stays under NVD's ~5 req/30s (no API key)

size_t curlWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    auto *out = reinterpret_cast<std::string *>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

// Performs the actual HTTP GET. Returns empty string on any failure.
#ifdef EPISCAN_HAVE_CURL
std::string httpGet(const std::string &url, int timeoutMs)
{
    CURL *curl = curl_easy_init();
    if (!curl) return {};

    std::string body;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeoutMs));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(timeoutMs));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "EpiScan/1.0 (+https://github.com/AfyliX/EpiScan)");

    const CURLcode res = curl_easy_perform(curl);
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || httpCode != 200) {
        return {};
    }
    return body;
}
#else
std::string httpGet(const std::string &, int)
{
    return {}; // built without libcurl — live NVD lookup unavailable, offline checks still work
}
#endif

std::vector<Vulnerability> parseNvdResponse(const std::string &json, const std::string &host, uint16_t port)
{
    std::vector<Vulnerability> findings;
    try {
        const auto root = nlohmann::json::parse(json);
        for (const auto &item : root.value("vulnerabilities", nlohmann::json::array())) {
            const auto &cve = item.at("cve");
            const std::string id = cve.value("id", "");
            if (id.empty()) continue;

            std::string description;
            for (const auto &desc : cve.value("descriptions", nlohmann::json::array())) {
                if (desc.value("lang", "") == "en") {
                    description = desc.value("value", "");
                    break;
                }
            }

            double cvss = 0.0;
            const auto &metrics = cve.value("metrics", nlohmann::json::object());
            if (metrics.contains("cvssMetricV31") && !metrics["cvssMetricV31"].empty()) {
                cvss = metrics["cvssMetricV31"][0].value("cvssData", nlohmann::json::object()).value("baseScore", 0.0);
            } else if (metrics.contains("cvssMetricV30") && !metrics["cvssMetricV30"].empty()) {
                cvss = metrics["cvssMetricV30"][0].value("cvssData", nlohmann::json::object()).value("baseScore", 0.0);
            } else if (metrics.contains("cvssMetricV2") && !metrics["cvssMetricV2"].empty()) {
                cvss = metrics["cvssMetricV2"][0].value("cvssData", nlohmann::json::object()).value("baseScore", 0.0);
            }

            Vulnerability v;
            v.id          = "network-nvd-" + id;
            v.file        = host + ":" + std::to_string(port);
            v.severity    = cvss >= 9.0 ? Severity::Critical
                           : cvss >= 7.0 ? Severity::High
                           : cvss >= 4.0 ? Severity::Medium
                                         : Severity::Low;
            v.message     = id + (description.empty() ? "" : (" — " + description));
            v.cwe         = "";
            v.remediation = "Consulter " + id + " sur https://nvd.nist.gov/vuln/detail/" + id + " et mettre à jour le service concerné";
            v.cvssScore   = cvss;
            v.category    = "network";
            findings.push_back(std::move(v));
        }
    } catch (const nlohmann::json::exception &) {
        // Malformed/unexpected NVD response shape — treat as no results.
    }
    return findings;
}

// ── Local cache ────────────────────────────────────────────────────────────

nlohmann::json loadCache()
{
    std::ifstream in(cacheFilePath());
    if (!in) return nlohmann::json::object();
    try {
        return nlohmann::json::parse(in);
    } catch (const nlohmann::json::exception &) {
        return nlohmann::json::object();
    }
}

void saveCache(const nlohmann::json &cache)
{
    const auto path = cacheFilePath();
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream out(path);
    if (out) out << cache.dump(2);
}

std::vector<Vulnerability> findingsFromCacheEntry(const nlohmann::json &entry, const std::string &host, uint16_t port)
{
    std::vector<Vulnerability> findings;
    for (const auto &f : entry.value("findings", nlohmann::json::array())) {
        Vulnerability v;
        v.id          = f.value("id", "");
        v.file        = host + ":" + std::to_string(port);
        v.severity    = severityFromString(f.value("severity", "low"));
        v.message     = f.value("message", "");
        v.remediation = f.value("remediation", "");
        v.cvssScore   = f.value("cvssScore", 0.0);
        v.category    = "network";
        findings.push_back(std::move(v));
    }
    return findings;
}

nlohmann::json cacheEntryFromFindings(const std::vector<Vulnerability> &findings, long nowEpoch)
{
    nlohmann::json entry;
    entry["timestamp"] = nowEpoch;
    entry["findings"]  = nlohmann::json::array();
    for (const auto &v : findings) {
        entry["findings"].push_back({
            {"id", v.id},
            {"severity", severityToString(v.severity)},
            {"message", v.message},
            {"remediation", v.remediation},
            {"cvssScore", v.cvssScore},
        });
    }
    return entry;
}

} // namespace

std::string guessCpe(const ServiceInfo &service)
{
    const std::string haystack = service.banner + " " + service.version;
    for (const auto &pattern : cpeProductPatterns()) {
        std::smatch match;
        if (std::regex_search(haystack, match, pattern.bannerPattern) && match.size() > 1) {
            return "cpe:2.3:a:" + pattern.vendor + ":" + pattern.product + ":" + match[1].str();
        }
    }
    return {};
}

std::vector<Vulnerability> lookupNvdCves(const ServiceInfo &service, const std::string &host)
{
    const std::string cpe = guessCpe(service);
    if (cpe.empty()) {
        return {};
    }

    const long nowEpoch = static_cast<long>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

    std::lock_guard<std::mutex> lock(g_nvdMutex);

    auto cache = loadCache();
    if (cache.contains(cpe)) {
        const auto &entry = cache[cpe];
        const long cachedAt = entry.value("timestamp", 0L);
        if (nowEpoch - cachedAt < k_cacheMaxAgeSeconds) {
            return findingsFromCacheEntry(entry, host, service.port);
        }
    }

    // Rate limit: NVD allows ~5 req/30s without an API key.
    const auto sinceLast = std::chrono::steady_clock::now() - g_lastRequest;
    if (sinceLast < k_minRequestInterval) {
        std::this_thread::sleep_for(k_minRequestInterval - sinceLast);
    }
    g_lastRequest = std::chrono::steady_clock::now();

    const std::string url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=" + cpe;
    const std::string body = httpGet(url, /*timeoutMs=*/8000);
    if (body.empty()) {
        return {}; // offline, rate-limited, WAF-blocked, or NVD down — fail silently
    }

    auto findings = parseNvdResponse(body, host, service.port);

    cache[cpe] = cacheEntryFromFindings(findings, nowEpoch);
    saveCache(cache);

    return findings;
}

} // namespace network
} // namespace episcan
