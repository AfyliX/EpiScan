#include "app/ScannerEngine.hpp"
#include "analyzer/CodeParser.hpp"
#include "core/Severity.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <vector>

namespace episcan {
namespace {

struct DetectionRule {
    std::string id;
    std::vector<std::string> requiredTokens;
    std::string severity;
    std::string message;
    std::string cwe;
    std::string remediation;
};

struct CommentState {
    bool inBlockC = false;
    bool inBlockHtml = false;
};

std::string toLowerAscii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

bool isLikelyTextFile(const std::filesystem::path &path)
{
    constexpr std::uintmax_t maxFileSizeBytes = 10 * 1024 * 1024;
    std::error_code errorCode;
    const auto fileSize = std::filesystem::file_size(path, errorCode);
    if (!errorCode && fileSize > maxFileSizeBytes) {
        return false;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }

    constexpr std::size_t sampleSize = 4096;
    std::string buffer(sampleSize, '\0');
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const auto bytesRead = input.gcount();
    if (bytesRead <= 0) {
        return false;
    }

    std::size_t controlBytes = 0;
    for (std::streamsize index = 0; index < bytesRead; ++index) {
        const unsigned char value = static_cast<unsigned char>(buffer[static_cast<std::size_t>(index)]);
        if (value == 0) {
            return false;
        }
        if (value < 9 || (value > 13 && value < 32)) {
            ++controlBytes;
        }
    }

    return (controlBytes * 20) <= static_cast<std::size_t>(bytesRead);
}

bool isLikelyCodeFile(const std::filesystem::path &path)
{
    const static std::unordered_set<std::string> codeExtensions = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
        ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".php",
        ".sh", ".bash", ".zsh", ".ps1", ".lua", ".swift", ".scala",
        ".pl", ".pm", ".cs", ".vb", ".sql", ".dart", ".r", ".m",
        ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
        ".xml", ".html", ".htm", ".css", ".scss", ".less"
    };

    const auto extension = toLowerAscii(path.extension().string());

    if (!extension.empty() && codeExtensions.find(extension) != codeExtensions.end()) {
        return true;
    }

    const auto filename = toLowerAscii(path.filename().string());
    return filename == "dockerfile" || filename == "makefile";
}

bool containsCaseInsensitive(const std::string &value, const std::string &needle)
{
    return toLowerAscii(value).find(toLowerAscii(needle)) != std::string::npos;
}

bool isNoiseReportJson(const std::filesystem::path &path)
{
    const auto extension = toLowerAscii(path.extension().string());
    const auto filename = toLowerAscii(path.filename().string());
    if (extension != ".json") {
        return false;
    }
    return filename.rfind("report", 0) == 0 || filename.rfind("episcan", 0) == 0;
}

bool isExcludedByDefault(const std::filesystem::path &path)
{
    const std::string asString = path.string();
    const std::string loweredPath = toLowerAscii(asString);

    if (containsCaseInsensitive(asString, "playwright")) {
        return true;
    }

    if (containsCaseInsensitive(asString, "/episcan/")
        || containsCaseInsensitive(asString, "\\episcan\\")) {
        return true;
    }

    static const std::vector<std::string> noisyPathParts = {
        "/.config/code/user/history/",
        "/.config/code/user/workspacestorage/",
        "/.local/share/trash/",
        "/snap/code/",
        "/tmp/episcan",
        "/tmp/scan_noise",
        "/tmp/escan_smoke_dataset",
        "/usr/src/linux-headers-",
        "/snap/searchsploit/",
        "/opt/exploitdb/"
    };

    for (const auto &part : noisyPathParts) {
        if (loweredPath.find(part) != std::string::npos) {
            return true;
        }
    }

    if (isNoiseReportJson(path)) {
        return true;
    }

    return false;
}

bool isScriptLikeFile(const std::filesystem::path &path)
{
    const static std::unordered_set<std::string> scriptExtensions = {
        ".sh", ".bash", ".zsh", ".ksh", ".ps1", ".bat", ".cmd"
    };

    const auto extension = toLowerAscii(path.extension().string());
    if (!extension.empty() && scriptExtensions.find(extension) != scriptExtensions.end()) {
        return true;
    }

    const auto filename = toLowerAscii(path.filename().string());
    return filename == "dockerfile";
}

bool hasExecutionSink(const std::string &loweredLine)
{
    static const std::vector<std::string> executionTokens = {
        "system(", "popen(", "execl(", "execlp(", "execle(", "execv(", "execvp(",
        "execve(", "runtime.getruntime().exec(", "processbuilder(", "subprocess.",
        "os.system(", "child_process.exec(", "child_process.execsync(",
        "child_process.spawn(", "powershell -command", "invoke-expression", "iex "
    };

    for (const auto &token : executionTokens) {
        if (loweredLine.find(token) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool isExecutableDangerContext(const std::filesystem::path &filePath, const std::string &loweredLine)
{
    if (isScriptLikeFile(filePath)) {
        return true;
    }

    return hasExecutionSink(loweredLine);
}

std::vector<DetectionRule> defaultRules()
{
    return {
        {"rm-rf-root", {"rm -rf"}, "critical", "Potential destructive wipe command",
         "CWE-78", "Never run rm -rf on user-controllable or system paths; require explicit confirmation and an allow-list of safe targets"},
        {"disk-format", {"mkfs."}, "critical", "Potential disk format command",
         "CWE-78", "Remove unattended disk-format commands; require interactive confirmation before formatting any device"},
        {"raw-disk-overwrite", {"dd if=/dev/zero", "of=/dev/"}, "critical", "Potential destructive raw disk overwrite",
         "CWE-78", "Avoid scripted raw writes to block devices; gate behind explicit operator confirmation"},
        {"curl-pipe-sh", {"curl", "| sh"}, "critical", "Potential download-and-execute payload",
         "CWE-494", "Never pipe a remote download directly into a shell; download, verify a checksum/signature, then execute"},
        {"curl-pipe-bash", {"curl", "| bash"}, "critical", "Potential download-and-execute payload",
         "CWE-494", "Never pipe a remote download directly into a shell; download, verify a checksum/signature, then execute"},
        {"wget-pipe-sh", {"wget", "| sh"}, "critical", "Potential download-and-execute payload",
         "CWE-494", "Never pipe a remote download directly into a shell; download, verify a checksum/signature, then execute"},
        {"wget-pipe-bash", {"wget", "| bash"}, "critical", "Potential download-and-execute payload",
         "CWE-494", "Never pipe a remote download directly into a shell; download, verify a checksum/signature, then execute"},
        {"nc-reverse-shell", {"nc", "-e"}, "high", "Potential reverse shell pattern",
         "CWE-78", "Remove netcat -e backdoor patterns; use proper remote-administration tooling with authentication"},
        {"bash-dev-tcp", {"/dev/tcp/", "bash -i"}, "high", "Potential reverse shell pattern",
         "CWE-78", "Remove interactive /dev/tcp reverse-shell patterns from scripts"},
        {"fork-bomb", {":(){ :|:& };:"}, "critical", "Fork bomb pattern",
         "CWE-400", "Remove unbounded self-forking constructs; enforce process/resource limits (ulimit, cgroups)"},
        {"setuid-root", {"setuid(0)", "exec"}, "high", "Potential privilege escalation pattern",
         "CWE-250", "Avoid dropping to setuid(0) before exec(); follow least-privilege and drop privileges instead of escalating"}
    };
}

std::string trimAscii(std::string value)
{
    auto notSpace = [](unsigned char character) {
        return !std::isspace(character);
    };

    value.erase(value.begin(), std::find_if(value.begin(), value.end(), notSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), notSpace).base(), value.end());
    return value;
}

bool hasRiskyDeviceTarget(const std::string &line)
{
    static const std::vector<std::string> riskyDevices = {
        "/dev/sd", "/dev/nvme", "/dev/vd", "/dev/mmcblk", "/dev/mapper/"
    };

    for (const auto &device : riskyDevices) {
        if (line.find(device) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool isDangerousRmTarget(const std::string &line)
{
    const auto rmPos = line.find("rm -rf");
    if (rmPos == std::string::npos) {
        return false;
    }

    const auto startPos = line.find('/', rmPos);
    if (startPos == std::string::npos) {
        return false;
    }

    std::size_t endPos = startPos;
    while (endPos < line.size()) {
        const char character = line[endPos];
        if (std::isspace(static_cast<unsigned char>(character))
            || character == ';'
            || character == '|'
            || character == '&'
            || character == '>'
            || character == '"'
            || character == '\''
            || character == ')') {
            break;
        }
        ++endPos;
    }

    const std::string target = trimAscii(line.substr(startPos, endPos - startPos));
    if (target.empty()) {
        return false;
    }

    static const std::vector<std::string> riskyPrefixes = {
        "/", "/etc", "/usr", "/var", "/home", "/root", "/boot", "/opt"
    };
    static const std::vector<std::string> safePrefixes = {
        "/tmp", "/mnt", "/media", "/run", "/var/tmp", "/dev/shm"
    };

    for (const auto &safe : safePrefixes) {
        if (target == safe || target.rfind(safe + "/", 0) == 0) {
            return false;
        }
    }

    for (const auto &risky : riskyPrefixes) {
        if (target == risky || target.rfind(risky + "/", 0) == 0) {
            return true;
        }
    }

    return false;
}

bool ruleMatchesStrict(const DetectionRule &rule, const std::string &loweredLine)
{
    bool allTokensMatched = true;
    for (const auto &token : rule.requiredTokens) {
        if (loweredLine.find(token) == std::string::npos) {
            allTokensMatched = false;
            break;
        }
    }

    if (!allTokensMatched) {
        return false;
    }

    if (rule.id == "rm-rf-root") {
        return isDangerousRmTarget(loweredLine);
    }

    if (rule.id == "disk-format") {
        return hasRiskyDeviceTarget(loweredLine);
    }

    if (rule.id == "raw-disk-overwrite") {
        return hasRiskyDeviceTarget(loweredLine);
    }

    if (rule.id == "nc-reverse-shell") {
        return loweredLine.find("nc -e ") != std::string::npos
            || loweredLine.find("/bin/nc -e ") != std::string::npos
            || loweredLine.find("netcat -e ") != std::string::npos;
    }

    return true;
}

bool startsWithAt(const std::string &value, std::size_t position, const std::string &prefix)
{
    return value.compare(position, prefix.size(), prefix) == 0;
}

bool isLikelyPreprocessorDirective(const std::string &line, std::size_t hashPosition)
{
    std::size_t index = hashPosition + 1;
    while (index < line.size() && std::isspace(static_cast<unsigned char>(line[index]))) {
        ++index;
    }

    const std::string directives[] = {
        "include", "define", "if", "ifdef", "ifndef", "elif", "else", "endif",
        "pragma", "error", "warning", "line", "undef", "import"
    };

    for (const auto &directive : directives) {
        if (line.compare(index, directive.size(), directive) == 0) {
            return true;
        }
    }

    return false;
}

std::string stripCommentsFromLine(const std::string &line, CommentState &state)
{
    std::string cleaned;
    cleaned.reserve(line.size());

    bool inString = false;
    char stringDelimiter = '\0';
    bool escaped = false;

    for (std::size_t index = 0; index < line.size();) {
        if (state.inBlockC) {
            const auto endPos = line.find("*/", index);
            if (endPos == std::string::npos) {
                return cleaned;
            }
            state.inBlockC = false;
            index = endPos + 2;
            continue;
        }

        if (state.inBlockHtml) {
            const auto endPos = line.find("-->", index);
            if (endPos == std::string::npos) {
                return cleaned;
            }
            state.inBlockHtml = false;
            index = endPos + 3;
            continue;
        }

        const char current = line[index];

        if (inString) {
            cleaned.push_back(current);
            if (escaped) {
                escaped = false;
            } else if (current == '\\') {
                escaped = true;
            } else if (current == stringDelimiter) {
                inString = false;
                stringDelimiter = '\0';
            }
            ++index;
            continue;
        }

        if (current == '"' || current == '\'' || current == '`') {
            inString = true;
            stringDelimiter = current;
            cleaned.push_back(current);
            ++index;
            continue;
        }

        if (startsWithAt(line, index, "/*")) {
            state.inBlockC = true;
            index += 2;
            continue;
        }

        if (startsWithAt(line, index, "<!--")) {
            state.inBlockHtml = true;
            index += 4;
            continue;
        }

        if (startsWithAt(line, index, "//")
            && (index == 0 || line[index - 1] != ':')) {
            break;
        }

        if (startsWithAt(line, index, "--")
            && (index == 0 || std::isspace(static_cast<unsigned char>(line[index - 1])))) {
            break;
        }

        if (current == '#') {
            if (cleaned.find_first_not_of(" \t") == std::string::npos
                && isLikelyPreprocessorDirective(line, index)) {
                cleaned.push_back(current);
                ++index;
                continue;
            }
            break;
        }

        cleaned.push_back(current);
        ++index;
    }

    return cleaned;
}

std::vector<Vulnerability> scanFile(
    const std::filesystem::path &filePath,
    const std::vector<DetectionRule> &rules)
{
    std::vector<Vulnerability> findings;

    // Rich, well-tested C/C++ analyzers (injection, crypto, unsafe functions,
    // buffer issues) — already populate CWE/CVSS/remediation/category per rule.
    auto analyzerFindings = analyzer::parseAndAnalyzeFile(filePath);
    findings.insert(findings.end(),
        std::make_move_iterator(analyzerFindings.begin()),
        std::make_move_iterator(analyzerFindings.end()));

    std::ifstream input(filePath);
    if (!input) {
        return findings;
    }

    std::string lineContent;
    CommentState commentState;
    std::size_t lineNumber = 0;

    while (std::getline(input, lineContent)) {
        ++lineNumber;
        const auto analyzableContent = stripCommentsFromLine(lineContent, commentState);
        const auto loweredLine = toLowerAscii(analyzableContent);
        if (analyzableContent.find_first_not_of(" \t") == std::string::npos) {
            continue;
        }

        for (const auto &rule : rules) {
            if (ruleMatchesStrict(rule, loweredLine)
                && isExecutableDangerContext(filePath, loweredLine)) {
                Vulnerability v;
                v.id          = rule.id;
                v.file        = filePath;
                v.line        = lineNumber;
                v.token       = rule.id;
                v.severity    = severityFromString(rule.severity);
                v.message     = rule.message;
                v.code        = analyzableContent;
                v.cwe         = rule.cwe;
                v.remediation = rule.remediation;
                v.cvssScore   = severityToCvss(v.severity);
                v.category    = "malicious-pattern";
                findings.push_back(std::move(v));
            }
        }
    }

    return findings;
}

bool pathStartsWith(const std::filesystem::path &path, const std::filesystem::path &prefix)
{
    auto pathIt = path.begin();
    auto prefixIt = prefix.begin();

    for (; prefixIt != prefix.end(); ++prefixIt, ++pathIt) {
        if (pathIt == path.end() || *pathIt != *prefixIt) {
            return false;
        }
    }

    return true;
}

bool shouldSkipDirectory(const std::filesystem::path &directoryPath, bool fullSystemScan)
{
    if (isExcludedByDefault(directoryPath)) {
        return true;
    }

    if (!fullSystemScan) {
        return false;
    }

    static const std::vector<std::filesystem::path> excludedPaths = {
        "/proc", "/sys", "/dev", "/run"
    };

    for (const auto &excludedPath : excludedPaths) {
        if (pathStartsWith(directoryPath, excludedPath)) {
            return true;
        }
    }

    return false;
}

} // namespace

ScanResult runScan(const ScanOptions &options, const ProgressCallback &onProgress)
{
    if (options.codePath.empty()) {
        throw std::runtime_error("Scan target path is empty");
    }

    if (!std::filesystem::exists(options.codePath)) {
        throw std::runtime_error("Target path does not exist: " + options.codePath.string());
    }

    if (!std::filesystem::is_directory(options.codePath) && !std::filesystem::is_regular_file(options.codePath)) {
        throw std::runtime_error("Target path must be a file or a directory");
    }

    const auto startTime = std::chrono::steady_clock::now();

    ScanResult result;
    const auto rules = defaultRules();
    std::vector<std::filesystem::path> candidates;

    if (std::filesystem::is_regular_file(options.codePath)) {
        // A single file was picked explicitly: scan it regardless of its extension,
        // only skipping it if it looks like binary content.
        if (isLikelyTextFile(options.codePath)) {
            candidates.push_back(options.codePath);
        }
    } else {
        const bool fullSystemScan = options.scanAllSystem || options.codePath == "/";
        std::error_code errorCode;
        std::filesystem::recursive_directory_iterator iterator(
            options.codePath,
            std::filesystem::directory_options::skip_permission_denied,
            errorCode);
        std::filesystem::recursive_directory_iterator end;

        if (errorCode) {
            return result;
        }

        while (iterator != end) {
            const auto currentPath = iterator->path();

            if (iterator->is_directory(errorCode)) {
                if (!errorCode && shouldSkipDirectory(currentPath, fullSystemScan)) {
                    iterator.disable_recursion_pending();
                }
                errorCode.clear();
                iterator.increment(errorCode);
                continue;
            }

            if (errorCode) {
                errorCode.clear();
                iterator.increment(errorCode);
                continue;
            }

            if (!iterator->is_regular_file(errorCode)) {
                errorCode.clear();
                iterator.increment(errorCode);
                continue;
            }

            if (isExcludedByDefault(currentPath)) {
                iterator.increment(errorCode);
                continue;
            }

            if (!isLikelyCodeFile(currentPath) || !isLikelyTextFile(currentPath)) {
                iterator.increment(errorCode);
                continue;
            }

            candidates.push_back(currentPath);
            errorCode.clear();
            iterator.increment(errorCode);
        }
    }

    result.scannedFiles = candidates.size();
    if (candidates.empty()) {
        if (onProgress) {
            onProgress({0, 0, {}});
        }
        result.durationSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - startTime).count();
        return result;
    }

    const unsigned int hardwareThreads = std::thread::hardware_concurrency();
    const std::size_t defaultThreads = hardwareThreads == 0 ? 4 : static_cast<std::size_t>(hardwareThreads);
    const std::size_t threadCount = std::max<std::size_t>(1, options.threadCount == 0 ? defaultThreads : options.threadCount);

    std::atomic<std::size_t> nextIndex {0};
    std::atomic<std::size_t> processed {0};
    std::mutex findingsMutex;
    std::mutex callbackMutex;
    std::vector<std::thread> workers;
    workers.reserve(threadCount);

    for (std::size_t workerId = 0; workerId < threadCount; ++workerId) {
        workers.emplace_back([&]() {
            while (true) {
                const std::size_t index = nextIndex.fetch_add(1);
                if (index >= candidates.size()) {
                    break;
                }

                const auto &filePath = candidates[index];
                auto fileFindings = scanFile(filePath, rules);
                if (!fileFindings.empty()) {
                    std::lock_guard<std::mutex> lock(findingsMutex);
                    result.findings.insert(result.findings.end(), fileFindings.begin(), fileFindings.end());
                }

                const std::size_t processedCount = processed.fetch_add(1) + 1;
                if (onProgress && (processedCount % 250 == 0 || processedCount == candidates.size())) {
                    std::lock_guard<std::mutex> lock(callbackMutex);
                    onProgress({processedCount, candidates.size(), filePath});
                }
            }
        });
    }

    for (auto &worker : workers) {
        worker.join();
    }

    result.durationSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - startTime).count();
    return result;
}

} // namespace episcan
