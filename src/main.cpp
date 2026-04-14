#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

struct Options {
    std::filesystem::path codePath;
    std::filesystem::path reportPath;
    bool showHelp = false;
};

struct DetectionRule {
    std::string token;
    std::string severity;
    std::string message;
};

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

void printUsage(const char *programName)
{
    std::cout << "Usage: " << programName << " --code <path> [--report <path>]\n"
              << "\n"
              << "Options:\n"
              << "  --code <path>      Directory to scan (required)\n"
              << "  --report <path>    Output report path (default: report.json)\n"
              << "  --help             Show this help message\n";
}

std::string escapeJson(const std::string &value)
{
    std::string escaped;
    escaped.reserve(value.size());

    for (char character : value) {
        switch (character) {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped += character;
            break;
        }
    }

    return escaped;
}

bool isSourceFile(const std::filesystem::path &path)
{
    static const std::vector<std::string> extensions = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"
    };
    const auto extension = path.extension().string();
    for (const auto &candidate : extensions) {
        if (extension == candidate) {
            return true;
        }
    }

    return false;
}

std::vector<DetectionRule> defaultRules()
{
    return {
        {"strcpy(", "high", "Use of unsafe copy function (buffer overflow risk)"},
        {"gets(", "critical", "Use of gets() is inherently unsafe"},
        {"system(", "medium", "Use of system() can lead to command injection"}
    };
}

std::vector<VulnerabilityFinding> scanFile(
    const std::filesystem::path &filePath,
    const std::vector<DetectionRule> &rules)
{
    std::ifstream input(filePath);
    if (!input) {
        return {};
    }
    std::vector<VulnerabilityFinding> findings;
    std::string lineContent;
    std::size_t lineNumber = 0;
    while (std::getline(input, lineContent)) {
        ++lineNumber;
        for (const auto &rule : rules) {
            if (lineContent.find(rule.token) != std::string::npos) {
                findings.push_back({
                    filePath,
                    lineNumber,
                    rule.token,
                    rule.severity,
                    rule.message,
                    lineContent,
                });
            }
        }
    }

    return findings;
}

ScanResult scanSourceTree(const std::filesystem::path &rootPath)
{
    ScanResult result;
    const auto rules = defaultRules();

    for (const auto &entry : std::filesystem::recursive_directory_iterator(rootPath)) {
        if (!entry.is_regular_file() || !isSourceFile(entry.path())) {
            continue;
        }
        ++result.scannedFiles;
        auto fileFindings = scanFile(entry.path(), rules);
        result.findings.insert(result.findings.end(), fileFindings.begin(), fileFindings.end());
    }
    return result;
}

std::string nowIso8601Utc()
{
    const auto now = std::chrono::system_clock::now();
    const std::time_t nowTime = std::chrono::system_clock::to_time_t(now);

    std::tm utcTime {};
#if defined(_WIN32)
    gmtime_s(&utcTime, &nowTime);
#else
    gmtime_r(&nowTime, &utcTime);
#endif

    std::ostringstream stream;
    stream << std::put_time(&utcTime, "%Y-%m-%dT%H:%M:%SZ");
    return stream.str();
}

Options parseArgs(int argc, char **argv)
{
    Options options;
    options.reportPath = "report.json";
    bool codePathAlreadySet = false;

    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];

        if (argument == "--help" || argument == "-h") {
            options.showHelp = true;
            return options;
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

void writeReport(const std::filesystem::path &reportPath,
    const std::filesystem::path &codePath,
    const ScanResult &scanResult)
{
    std::ofstream output(reportPath);
    if (!output) {
        throw std::runtime_error("Unable to open report file: " + reportPath.string());
    }

    output << "{\n";
    output << "  \"tool\": \"EpiScan\",\n";
    output << "  \"generated_at\": \"" << nowIso8601Utc() << "\",\n";
    output << "  \"target_path\": \"" << escapeJson(codePath.string()) << "\",\n";
    output << "  \"summary\": {\n";
    output << "    \"scanned_files\": " << scanResult.scannedFiles << ",\n";
    output << "    \"detected_vulnerabilities\": " << scanResult.findings.size() << "\n";
    output << "  },\n";
    output << "  \"vulnerabilities\": [\n";

    for (std::size_t index = 0; index < scanResult.findings.size(); ++index) {
        const auto &finding = scanResult.findings[index];
        const bool isLast = (index + 1 == scanResult.findings.size());

        output << "    {\n";
        output << "      \"file\": \"" << escapeJson(finding.file.string()) << "\",\n";
        output << "      \"line\": " << finding.line << ",\n";
        output << "      \"rule\": \"" << escapeJson(finding.matchedToken) << "\",\n";
        output << "      \"severity\": \"" << escapeJson(finding.severity) << "\",\n";
        output << "      \"message\": \"" << escapeJson(finding.message) << "\",\n";
        output << "      \"code\": \"" << escapeJson(finding.code) << "\"\n";
        output << "    }" << (isLast ? "\n" : ",\n");
    }

    output << "  ]\n";
    output << "}\n";
}

} // namespace

int main(int argc, char **argv)
{
    try {
        const Options options = parseArgs(argc, argv);

        if (options.showHelp) {
            printUsage(argv[0]);
            return 0;
        }

        if (options.codePath.empty()) {
            std::cerr << "Error: --code is required.\n\n";
            printUsage(argv[0]);
            return 1;
        }

        if (!std::filesystem::exists(options.codePath)) {
            std::cerr << "Error: path does not exist: " << options.codePath << "\n";
            return 1;
        }

        if (!std::filesystem::is_directory(options.codePath)) {
            std::cerr << "Error: --code must point to a directory.\n";
            return 1;
        }

        const auto scanResult = scanSourceTree(options.codePath);
        writeReport(options.reportPath, options.codePath, scanResult);

        std::cout << "Scan completed.\n";
        std::cout << "Source files scanned: " << scanResult.scannedFiles << "\n";
        std::cout << "Detected vulnerabilities: " << scanResult.findings.size() << "\n";
        std::cout << "Report written to: " << options.reportPath << "\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "Error: " << error.what() << "\n";
        return 1;
    }
}
