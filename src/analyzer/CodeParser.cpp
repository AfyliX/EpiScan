#include "analyzer/CodeParser.hpp"
#include "analyzer/CryptoDetector.hpp"
#include "analyzer/InjectionDetector.hpp"
#include "analyzer/UnsafeFunctionDetector.hpp"
#include "analyzer/VulnDetector.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <system_error>
#include <unordered_set>

namespace episcan {
namespace analyzer {
namespace {

bool isLikelyCodeFile(const std::filesystem::path &p)
{
    static const std::unordered_set<std::string> exts = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".py", ".js", ".ts", ".php", ".java", ".go", ".rb",
        ".yaml", ".yml", ".toml", ".conf", ".ini", ".env",
        ".sh", ".bash"
    };
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return exts.count(ext) > 0;
}

bool isExcludedPath(const std::filesystem::path &p)
{
    const std::string s = p.string();
    return s.find("/.git/")   != std::string::npos
        || s.find("/build/")  != std::string::npos
        || s.find("/cmake/")  != std::string::npos
        || s.find("CMakeFiles") != std::string::npos;
}

void appendFindings(std::vector<Vulnerability> &dst,
                    std::vector<Vulnerability>  src)
{
    dst.insert(dst.end(),
               std::make_move_iterator(src.begin()),
               std::make_move_iterator(src.end()));
}

} // namespace

std::vector<Vulnerability> parseAndAnalyzeFile(const std::filesystem::path &file,
                                                const ScanConfig            &cfg)
{
    std::vector<Vulnerability> results;

    if (cfg.enableCode) {
        appendFindings(results, detectUnsafeFunctions(file));
    }
    if (cfg.enableInjection) {
        appendFindings(results, detectInjections(file));
    }
    if (cfg.enableCrypto) {
        appendFindings(results, detectCryptoIssues(file));
    }
    if (cfg.enableBuffer) {
        appendFindings(results, detectBufferVulns(file));
    }

    // Apply CVSS threshold filter
    if (cfg.minCvssThreshold > 0.0) {
        results.erase(
            std::remove_if(results.begin(), results.end(),
                [&](const Vulnerability &v) { return v.cvssScore < cfg.minCvssThreshold; }),
            results.end());
    }

    return results;
}

std::vector<Vulnerability> analyzeDirectory(const std::filesystem::path &dir,
                                             const ScanConfig            &cfg,
                                             std::size_t                 *scannedFiles)
{
    std::vector<Vulnerability> all;
    std::size_t count = 0;

    std::error_code ec;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(dir,
             std::filesystem::directory_options::skip_permission_denied, ec))
    {
        if (ec) { ec.clear(); continue; }
        if (!entry.is_regular_file(ec)) { ec.clear(); continue; }
        const auto &path = entry.path();
        if (isExcludedPath(path))    continue;
        if (!isLikelyCodeFile(path)) continue;

        ++count;
        auto findings = parseAndAnalyzeFile(path, cfg);
        all.insert(all.end(),
                   std::make_move_iterator(findings.begin()),
                   std::make_move_iterator(findings.end()));

        if (cfg.maxFindings > 0 && all.size() >= cfg.maxFindings) break;
    }

    if (scannedFiles) *scannedFiles = count;
    return all;
}

} // namespace analyzer
} // namespace episcan
