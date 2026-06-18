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
    bool        hasPreviousScan = false;
    long        totalDelta      = 0; // total - previous scan's total (only valid if hasPreviousScan)
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

// Picks JSON/HTML/Markdown based on the path's extension (.html/.htm, .md/.markdown,
// anything else falls back to JSON).
void writeReportAuto(const std::filesystem::path &path, const Report &report);

// If a previous JSON report exists at previousReportPath, reads its summary "total"
// and fills report.summary.hasPreviousScan / totalDelta. No-op if not found/unreadable.
void applyPreviousScanDelta(Report &report, const std::filesystem::path &previousReportPath);

} // namespace episcan
