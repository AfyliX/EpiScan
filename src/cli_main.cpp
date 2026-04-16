#include "app/ScannerEngine.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

struct CliOptions {
    std::filesystem::path codePath;
    std::filesystem::path reportPath = "report.json";
    bool scanAllSystem = false;
    bool showHelp = false;
};

void printUsage(const char *programName)
{
    std::cout << "Usage: " << programName << " --code <path> [--report <path>]\n"
              << "       " << programName << " --all-system [--report <path>]\n"
              << "\n"
              << "Options:\n"
              << "  --code <path>      Directory to scan\n"
              << "  --all-system       Scan the whole system from / (Linux)\n"
              << "  --report <path>    Output report path (default: report.json)\n"
              << "  --help             Show this help message\n";
}

CliOptions parseArgs(int argc, char **argv)
{
    CliOptions options;
    bool codePathAlreadySet = false;

    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];

        if (argument == "--help" || argument == "-h") {
            options.showHelp = true;
            return options;
        }

        if (argument == "--all-system") {
            options.scanAllSystem = true;
            continue;
        }

        if (argument == "--code") {
            if (index + 1 >= argc) {
                throw std::runtime_error("Missing value for --code");
            }
            if (codePathAlreadySet) {
                throw std::runtime_error("Code path provided multiple times");
            }
            options.codePath = argv[++index];
            codePathAlreadySet = true;
            continue;
        }

        if (argument == "--report") {
            if (index + 1 >= argc) {
                throw std::runtime_error("Missing value for --report");
            }
            options.reportPath = argv[++index];
            continue;
        }

        if (!argument.empty() && argument[0] != '-') {
            if (codePathAlreadySet) {
                throw std::runtime_error("Code path provided multiple times");
            }
            options.codePath = argument;
            codePathAlreadySet = true;
            continue;
        }

        throw std::runtime_error("Unknown argument: " + argument);
    }

    return options;
}

} // namespace

int main(int argc, char **argv)
{
    try {
        auto options = parseArgs(argc, argv);

        if (options.showHelp) {
            printUsage(argv[0]);
            return 0;
        }

        if (options.codePath.empty()) {
            if (options.scanAllSystem) {
                options.codePath = "/";
            } else {
                std::cerr << "Error: --code is required.\n\n";
                printUsage(argv[0]);
                return 1;
            }
        }

        if (options.scanAllSystem && options.codePath != "/") {
            std::cerr << "Error: use either --all-system or --code <path>, not both.\n";
            return 1;
        }

        episcan::ScanOptions scanOptions;
        scanOptions.codePath = options.codePath;
        scanOptions.reportPath = options.reportPath;
        scanOptions.scanAllSystem = options.scanAllSystem;

        std::cout << "[scan] target: " << scanOptions.codePath << "\n";
        const auto result = episcan::runScan(scanOptions, [](const episcan::ScanProgress &progress) {
            if (progress.totalFiles == 0) {
                return;
            }
            std::cout << "[scan] " << progress.processedFiles << "/" << progress.totalFiles
                      << " | current: " << progress.currentFile << "\n";
        });

        episcan::writeReport(scanOptions.reportPath, scanOptions.codePath, result);

        std::cout << "Scan completed.\n";
        std::cout << "Text files scanned: " << result.scannedFiles << "\n";
        std::cout << "Detected vulnerabilities: " << result.findings.size() << "\n";
        std::cout << "Report written to: " << scanOptions.reportPath << "\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "Error: " << error.what() << "\n";
        return 1;
    }
}
