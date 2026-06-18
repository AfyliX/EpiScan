#pragma once

#include "core/Vulnerability.hpp"

#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace episcan {

struct ScanResult {
    std::size_t scannedFiles = 0;
    double      durationSec  = 0.0;
    std::vector<Vulnerability> findings;
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

} // namespace episcan
