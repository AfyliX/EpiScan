#pragma once
#include "Vulnerability.hpp"
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace episcan {

struct ReportSummary {
    std::size_t critical = 0;
    std::size_t high     = 0;
    std::size_t medium   = 0;
    std::size_t low      = 0;
    std::size_t total    = 0;
    double      securityScore = 100.0; // 0–100, decreases with findings
    std::size_t scannedFiles  = 0;
    std::size_t scannedPorts  = 0;
    double      scanDurationSec = 0.0;
};

struct Report {
    std::string              scanDate;
    std::string              target;
    ReportSummary            summary;
    std::vector<Vulnerability> findings;
};

Report buildReport(const std::string              &target,
                   const std::vector<Vulnerability> &findings,
                   std::size_t                      scannedFiles  = 0,
                   std::size_t                      scannedPorts  = 0,
                   double                           durationSec   = 0.0);

void writeReportJson(const std::filesystem::path &path, const Report &report);
void writeReportHtml(const std::filesystem::path &path, const Report &report);
void writeReportMarkdown(const std::filesystem::path &path, const Report &report);

} // namespace episcan
