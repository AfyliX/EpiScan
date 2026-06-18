#include "app/ScannerEngine.hpp"
#include "core/Report.hpp"
#include "core/Metrics.hpp"
#include "network/NetworkvulAnalyzer.hpp"

#include <CLI/CLI.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>

namespace {

std::filesystem::path applyFormat(std::filesystem::path reportPath, const std::string &format)
{
    if (format.empty())      return reportPath;
    if (format == "json")    reportPath.replace_extension(".json");
    else if (format == "html") reportPath.replace_extension(".html");
    else if (format == "md")   reportPath.replace_extension(".md");
    return reportPath;
}

} // namespace

int main(int argc, char **argv)
{
    CLI::App app{"EpiScan — static code and network security scanner", "episcan-cli"};
    app.set_version_flag("--version", std::string("EpiScan CLI"));

    std::string codePathStr;
    std::string networkTarget;
    std::string reportPathStr = "report.json";
    std::string format;
    bool        allSystem = false;
    uint16_t    portStart = 1;
    uint16_t    portEnd   = 1024;
    bool        cveCheck  = false;

    app.add_option("--code", codePathStr, "Directory or file to scan for code vulnerabilities (analyze mode)");
    app.add_flag("--all-system", allSystem, "Scan the whole system from / (Linux only, analyze mode)");
    app.add_option("--network", networkTarget, "Host to run a network scan against (ports, banners, SSL audit; network mode)");
    app.add_option("--port-start", portStart, "First port for --network")->default_val(1);
    app.add_option("--port-end", portEnd, "Last port for --network")->default_val(1024);
    app.add_flag("--cve-check", cveCheck, "Query the NVD REST API for live CVE data (requires internet; off by default)");
    app.add_option("--report", reportPathStr, "Output report path")->default_val("report.json");
    app.add_option("--format", format, "Report format: json, html, or md (default: inferred from --report extension)")
        ->check(CLI::IsMember({"json", "html", "md"}));

    app.footer(
        "Examples:\n"
        "  episcan-cli --code ./src --report report.html\n"
        "  episcan-cli --network 192.168.1.10 --port-end 65535 --report net.json\n"
        "  episcan-cli --network 192.168.1.10 --cve-check --report net.json\n"
        "  episcan-cli --code ./src --network 127.0.0.1 --report full.md --format md\n"
        "\n"
        "Pass both --code and --network to run a combined \"full\" scan.\n"
        "--cve-check queries the NVD REST API (internet required); results are cached\n"
        "for 7 days under ~/.cache/episcan/nvd_cache.json.");

    CLI11_PARSE(app, argc, argv);

    try {
        std::filesystem::path codePath = allSystem ? std::filesystem::path("/") : std::filesystem::path(codePathStr);

        const bool wantsCode    = allSystem || !codePathStr.empty();
        const bool wantsNetwork = !networkTarget.empty();

        if (!wantsCode && !wantsNetwork) {
            std::cerr << "Error: provide --code, --all-system, or --network.\n\n" << app.help();
            return 1;
        }
        if (allSystem && !codePathStr.empty() && codePath != "/") {
            std::cerr << "Error: use either --all-system or --code <path>, not both.\n";
            return 1;
        }

        const auto reportPath = applyFormat(reportPathStr, format);

        std::vector<episcan::Vulnerability> allFindings;
        std::size_t scannedFiles = 0;
        std::size_t scannedPorts = 0;
        double      totalDurationSec = 0.0;
        std::map<std::string, double> durationByModule;

        std::string target = wantsCode ? codePath.string() : networkTarget;

        if (wantsCode) {
            episcan::ScanOptions scanOptions;
            scanOptions.codePath      = codePath;
            scanOptions.scanAllSystem = allSystem;

            std::cout << "[scan] code target: " << scanOptions.codePath << "\n";
            const auto result = episcan::runScan(scanOptions, [](const episcan::ScanProgress &progress) {
                if (progress.totalFiles == 0) return;
                std::cout << "[scan] " << progress.processedFiles << "/" << progress.totalFiles
                          << " | current: " << progress.currentFile << "\n";
            });

            allFindings.insert(allFindings.end(), result.findings.begin(), result.findings.end());
            scannedFiles += result.scannedFiles;
            totalDurationSec += result.durationSec;
            durationByModule["code"] = result.durationSec;
        }

        if (wantsNetwork) {
            episcan::network::NetworkScanOptions netOptions;
            netOptions.target    = networkTarget;
            netOptions.portStart = portStart;
            netOptions.portEnd   = portEnd;
            netOptions.sslAudit  = true;
            netOptions.cveCheck  = cveCheck;

            std::cout << "[scan] network target: " << netOptions.target
                       << " ports " << netOptions.portStart << "-" << netOptions.portEnd << "\n";

            const auto netStart = std::chrono::steady_clock::now();
            const auto result = episcan::network::analyzeNetwork(netOptions);
            const double netDuration = std::chrono::duration<double>(std::chrono::steady_clock::now() - netStart).count();

            allFindings.insert(allFindings.end(), result.findings.begin(), result.findings.end());
            scannedPorts += result.scannedPorts;
            totalDurationSec += netDuration;
            durationByModule["network"] = netDuration;

            std::cout << "[scan] open services found: " << result.services.size() << "\n";
        }

        if (wantsCode && wantsNetwork) {
            target = codePath.string() + " + " + networkTarget;
        }

        auto report = episcan::buildReport(target, allFindings, scannedFiles, scannedPorts, totalDurationSec);
        episcan::applyPreviousScanDelta(report, reportPath);
        episcan::writeReportAuto(reportPath, report);

        auto metrics = episcan::computeMetrics(allFindings, scannedFiles, scannedPorts, totalDurationSec);
        metrics.durationByModule = durationByModule;

        std::cout << "\nScan completed.\n";
        std::cout << "Files scanned: " << scannedFiles << " | Ports scanned: " << scannedPorts << "\n";
        std::cout << "Findings: " << allFindings.size() << " | Security score: "
                  << report.summary.securityScore << "/100\n";
        if (report.summary.hasPreviousScan) {
            std::cout << "Delta vs previous scan: "
                       << (report.summary.totalDelta >= 0 ? "+" : "") << report.summary.totalDelta << " findings\n";
        }
        std::cout << "Report written to: " << reportPath << "\n";

        episcan::printMetrics(metrics);
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "Error: " << error.what() << "\n";
        return 1;
    }
}
