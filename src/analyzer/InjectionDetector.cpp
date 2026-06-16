#include "analyzer/InjectionDetector.hpp"
#include "core/Severity.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <regex>
#include <string>
#include <unordered_set>

namespace episcan {
namespace analyzer {
namespace {

struct InjRule {
    std::string  id;
    std::regex   pattern;
    std::string  message;
    std::string  cwe;
    std::string  remediation;
    Severity     severity;
    double       cvss;
    std::string  category;
};

const std::vector<InjRule> &injectionRules()
{
    static const std::vector<InjRule> rules = {
        {
            "sql-concat-string",
            std::regex(R"((\"SELECT|\"INSERT|\"UPDATE|\"DELETE|\"FROM|\"WHERE)[^\"]*\"\s*\+)",
                       std::regex::icase),
            "Concaténation SQL avec variable — injection possible",
            "CWE-89",
            "Utiliser des requêtes préparées (prepared statements) avec paramètres liés",
            Severity::High, 8.5, "injection"
        },
        {
            "sql-concat-plus-var",
            std::regex(R"(\+\s*(user|input|param|req\.|request\.|argv|cin|getline)\w*)",
                       std::regex::icase),
            "Concaténation directe d'une entrée utilisateur dans une requête SQL",
            "CWE-89",
            "Paramétrer les requêtes SQL — ne jamais concaténer l'input utilisateur",
            Severity::High, 8.0, "injection"
        },
        {
            "cmd-injection-system",
            std::regex(R"(system\s*\([^)]*\+[^)]*\))", std::regex::icase),
            "system() avec concaténation — injection de commande",
            "CWE-78",
            "Éviter system(); utiliser execve() avec argv séparé",
            Severity::Critical, 9.5, "injection"
        },
        {
            "cmd-injection-popen",
            std::regex(R"(popen\s*\([^)]*\+[^)]*\))", std::regex::icase),
            "popen() avec concaténation — injection de commande",
            "CWE-78",
            "Éviter popen(); construire la commande sans entrée utilisateur",
            Severity::Critical, 9.5, "injection"
        },
        {
            "path-traversal-fopen",
            std::regex(R"((fopen|open|ifstream)\s*\([^)]*\.\.[^)]*\))", std::regex::icase),
            "Chemin avec '..' — traversée de répertoire possible",
            "CWE-22",
            "Normaliser et valider les chemins; utiliser realpath() et comparer au répertoire racine",
            Severity::High, 7.5, "injection"
        },
        {
            "path-traversal-user-input",
            std::regex(R"((fopen|open|ifstream)\s*\([^)]*\+[^)]*\))", std::regex::icase),
            "fopen/open avec concaténation — traversée de chemin potentielle",
            "CWE-22",
            "Valider et sanitiser le chemin avant utilisation",
            Severity::Medium, 6.0, "injection"
        },
        {
            "format-string",
            std::regex(R"(printf\s*\(\s*(argv|user|input|param)\w*\s*\))", std::regex::icase),
            "printf() avec format string non contrôlé",
            "CWE-134",
            "Utiliser printf(\"%s\", input) — ne jamais passer l'input comme premier arg",
            Severity::High, 8.0, "injection"
        },
    };
    return rules;
}

bool isCodeFile(const std::filesystem::path &p)
{
    static const std::unordered_set<std::string> exts = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
        ".py", ".js", ".ts", ".php", ".java", ".go", ".rb"
    };
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return exts.count(ext) > 0;
}

} // namespace

std::vector<Vulnerability> detectInjections(const std::filesystem::path &file)
{
    if (!isCodeFile(file)) return {};

    std::ifstream in(file);
    if (!in) return {};

    std::vector<Vulnerability> results;
    std::string line;
    std::size_t lineNum = 0;

    while (std::getline(in, line)) {
        ++lineNum;
        const auto commentPos = line.find("//");
        const std::string code = (commentPos != std::string::npos)
                                   ? line.substr(0, commentPos)
                                   : line;
        if (code.find_first_not_of(" \t") == std::string::npos) continue;

        for (const auto &rule : injectionRules()) {
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
                v.category    = rule.category;
                results.push_back(std::move(v));
                break;
            }
        }
    }
    return results;
}

} // namespace analyzer
} // namespace episcan
