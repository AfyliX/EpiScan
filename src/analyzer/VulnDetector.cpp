#include "analyzer/VulnDetector.hpp"
#include "core/Severity.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <regex>
#include <string>
#include <unordered_set>
#include <vector>

namespace episcan {
namespace analyzer {
namespace {

struct BufferRule {
    std::string id;
    std::regex  pattern;
    std::string message;
    std::string cwe;
    std::string remediation;
    Severity    severity;
    double      cvss;
};

const std::vector<BufferRule> &bufferRules()
{
    static const std::vector<BufferRule> rules = {
        {
            "array-no-bounds",
            std::regex(R"(\w+\s*\[\s*\w+\s*\]\s*=)", std::regex::icase),
            "Accès tableau sans vérification de bornes",
            "CWE-125",
            "Vérifier que l'index est dans les limites du tableau avant accès",
            Severity::Medium, 6.0
        },
        {
            "free-then-use",
            std::regex(R"(\bfree\s*\(\s*(\w+)\s*\))", std::regex::icase),
            "Appel free() — vérifier l'absence d'utilisation post-libération",
            "CWE-416",
            "Mettre le pointeur à NULL après free(); utiliser smart pointers en C++",
            Severity::High, 8.0
        },
        {
            "double-free-pattern",
            std::regex(R"(free\s*\(\s*\w+\s*\)\s*;?\s*\n[\s\S]{0,200}free\s*\(\s*\w+\s*\))",
                       std::regex::icase),
            "Pattern de double-free potentiel",
            "CWE-415",
            "Utiliser des smart pointers; mettre le pointeur à NULL après free()",
            Severity::Critical, 9.0
        },
        {
            "malloc-no-check",
            std::regex(R"(\w+\s*=\s*malloc\s*\([^)]+\)\s*;(?!\s*if))", std::regex::icase),
            "malloc() sans vérification du pointeur retourné",
            "CWE-252",
            "Vérifier que malloc() ne retourne pas NULL avant utilisation",
            Severity::Medium, 5.5
        },
        {
            "memcpy-no-bounds",
            std::regex(R"(memcpy\s*\([^,]+,\s*[^,]+,\s*\w+\s*\))", std::regex::icase),
            "memcpy() — vérifier que la taille ne dépasse pas le buffer destination",
            "CWE-120",
            "Vérifier les tailles source et destination; préférer std::copy avec span",
            Severity::Medium, 6.5
        },
        {
            "memset-size-mismatch",
            std::regex(R"(memset\s*\(\s*\w+\s*,\s*\d+\s*,\s*sizeof\s*\(\s*\w+\s*\*\s*\)\s*\))",
                       std::regex::icase),
            "memset avec sizeof(ptr) au lieu de sizeof(*ptr) — taille incorrecte",
            "CWE-131",
            "Utiliser sizeof(*ptr) pour obtenir la taille de la structure pointée",
            Severity::High, 7.0
        },
        {
            "stack-alloc-variable",
            std::regex(R"(\w+\s+\w+\s*\[\s*\w+\s*\]\s*;)", std::regex::icase),
            "Tableau de taille variable sur la pile (VLA) — risque de débordement",
            "CWE-121",
            "Utiliser une allocation dynamique ou un conteneur std::vector",
            Severity::Low, 3.5
        },
        {
            "uninit-var-use",
            std::regex(R"(int\s+\w+\s*;(?!\s*(=|\{)))", std::regex::icase),
            "Variable entière déclarée sans initialisation",
            "CWE-457",
            "Initialiser toutes les variables à la déclaration",
            Severity::Low, 3.0
        },
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

std::vector<Vulnerability> detectBufferVulns(const std::filesystem::path &file)
{
    if (!isCCodeFile(file)) return {};

    std::ifstream in(file);
    if (!in) return {};

    std::vector<Vulnerability> results;
    std::string line;
    std::size_t lineNum = 0;

    // Skip double-free multi-line rule (applied on full content separately)
    std::string fullContent;
    while (std::getline(in, line)) {
        ++lineNum;
        const auto commentPos = line.find("//");
        const std::string code = (commentPos != std::string::npos)
                                   ? line.substr(0, commentPos)
                                   : line;
        fullContent += code + "\n";

        if (code.find_first_not_of(" \t") == std::string::npos) continue;

        for (const auto &rule : bufferRules()) {
            if (rule.id == "double-free-pattern") continue; // handled below
            if (std::regex_search(code, rule.pattern)) {
                Vulnerability v;
                v.id          = rule.id;
                v.file        = file;
                v.line        = lineNum;
                v.token       = rule.id;
                v.severity    = rule.severity;
                v.message     = rule.message;
                v.code        = code.substr(code.find_first_not_of(" \t"));
                v.cwe         = rule.cwe;
                v.remediation = rule.remediation;
                v.cvssScore   = rule.cvss;
                v.category    = "buffer";
                results.push_back(std::move(v));
                break;
            }
        }
    }

    // Multi-line double-free check
    const auto &dfRule = bufferRules()[2]; // double-free-pattern
    if (std::regex_search(fullContent, dfRule.pattern)) {
        Vulnerability v;
        v.id          = dfRule.id;
        v.file        = file;
        v.line        = 0;
        v.token       = dfRule.id;
        v.severity    = dfRule.severity;
        v.message     = dfRule.message;
        v.code        = "(multi-lignes)";
        v.cwe         = dfRule.cwe;
        v.remediation = dfRule.remediation;
        v.cvssScore   = dfRule.cvss;
        v.category    = "buffer";
        results.push_back(std::move(v));
    }

    return results;
}

} // namespace analyzer
} // namespace episcan
