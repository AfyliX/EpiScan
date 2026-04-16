#pragma once

#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace episcan {

struct VulnerabilityFinding {
    std::filesystem::path file;
    std::size_t line = 0;
    std::string matchedToken;
    std::string severity;
    std::string message;
    std::string code;
};

struct ScanResult {
    std::size_t scannedFiles = 0;
    std::vector<VulnerabilityFinding> findings;
};

struct ScanProgress {
    std::size_t processedFiles = 0;
    std::size_t totalFiles = 0;
    std::filesystem::path currentFile;
};

struct ScanOptions {
    std::filesystem::path codePath;
    std::filesystem::path reportPath = "report.json";
    bool scanAllSystem = false;
    std::size_t threadCount = 0;
};

using ProgressCallback = std::function<void(const ScanProgress &)>;

ScanResult runScan(const ScanOptions &options, const ProgressCallback &onProgress = {});
void writeReport(const std::filesystem::path &reportPath,
    const std::filesystem::path &codePath,
    const ScanResult &scanResult);

} // namespace episcan
