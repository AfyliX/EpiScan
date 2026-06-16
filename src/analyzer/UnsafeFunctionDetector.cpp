#include "analyzer/UnsafeFunctionDetector.hpp"
#include "core/Severity.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <string>
#include <unordered_set>

namespace episcan {
namespace analyzer {
namespace {

struct UnsafeRule {
    std::string token;
    std::string alternative;
    std::string cwe;
    std::string message;
    Severity    severity;
    double      cvss;
};

const std::vector<UnsafeRule> &unsafeRules()
{
    static const std::vector<UnsafeRule> rules = {
        {"gets(",     "fgets()",               "CWE-120", "gets() — buffer overflow garanti", Severity::Critical, 9.8},
        {"strcpy(",   "strncpy() / std::string","CWE-120", "strcpy() — pas de vérification de taille", Severity::High, 7.5},
        {"strcat(",   "strncat()",              "CWE-120", "strcat() — possible débordement de buffer", Severity::High, 7.5},
        {"sprintf(",  "snprintf()",             "CWE-120", "sprintf() — pas de limite de taille", Severity::High, 7.5},
        {"vsprintf(", "vsnprintf()",            "CWE-120", "vsprintf() — pas de limite de taille", Severity::High, 7.5},
        {"scanf(",    "fgets() + sscanf()",     "CWE-120", "scanf() — peut déborder si format incorrect", Severity::Medium, 6.5},
        {"sscanf(",   "sscanf() avec format contrôlé","CWE-120", "sscanf() — vérifier le format", Severity::Low, 3.5},
        {"strlen(",   "strnlen()",              "CWE-170", "strlen() — potentiel si string non terminée", Severity::Low, 2.5},
        {"system(",   "execve()",               "CWE-78",  "system() — injection de commande possible", Severity::Critical, 9.0},
        {"popen(",    "execve() + pipe()",      "CWE-78",  "popen() — injection de commande possible", Severity::High, 8.0},
        {"rand(",     "/dev/urandom ou <random>","CWE-338","rand() — PRNG faible, ne pas utiliser pour crypto", Severity::Medium, 5.0},
        {"srand(time", "/dev/urandom",          "CWE-338", "srand(time(0)) — seed prévisible", Severity::Medium, 5.0},
        {"mktemp(",   "mkstemp()",              "CWE-377", "mktemp() — TOCTOU sur fichiers temporaires", Severity::Medium, 5.5},
        {"tmpnam(",   "tmpfile() / mkstemp()",  "CWE-377", "tmpnam() — condition de concurrence", Severity::Medium, 5.5},
        {"alloca(",   "stack allocation limitée","CWE-121","alloca() — dépassement de pile possible", Severity::Medium, 5.0},
    };
    return rules;
}

bool isCCodeFile(const std::filesystem::path &p)
{
    static const std::unordered_set<std::string> exts = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"
    };
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return exts.count(ext) > 0;
}

} // namespace

std::vector<Vulnerability> detectUnsafeFunctions(const std::filesystem::path &file)
{
    if (!isCCodeFile(file)) return {};

    std::ifstream in(file);
    if (!in) return {};

    std::vector<Vulnerability> results;
    std::string line;
    std::size_t lineNum = 0;

    while (std::getline(in, line)) {
        ++lineNum;
        // Strip line comments
        const auto commentPos = line.find("//");
        const std::string code = (commentPos != std::string::npos)
                                   ? line.substr(0, commentPos)
                                   : line;

        for (const auto &rule : unsafeRules()) {
            if (code.find(rule.token) != std::string::npos) {
                Vulnerability v;
                v.id          = "unsafe-" + rule.token.substr(0, rule.token.size() - 1);
                v.file        = file;
                v.line        = lineNum;
                v.token       = rule.token;
                v.severity    = rule.severity;
                v.message     = rule.message;
                v.code        = code.substr(code.find_first_not_of(" \t"));
                v.cwe         = rule.cwe;
                v.remediation = "Utiliser " + rule.alternative + " à la place de " + rule.token;
                v.cvssScore   = rule.cvss;
                v.category    = "unsafe_func";
                results.push_back(std::move(v));
                break; // une seule règle par ligne
            }
        }
    }
    return results;
}

} // namespace analyzer
} // namespace episcan
