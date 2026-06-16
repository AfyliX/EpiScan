#include "analyzer/CryptoDetector.hpp"
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

struct CryptoRule {
    std::string id;
    std::regex  pattern;
    std::string message;
    std::string cwe;
    std::string remediation;
    Severity    severity;
    double      cvss;
};

const std::vector<CryptoRule> &cryptoRules()
{
    static const std::vector<CryptoRule> rules = {
        {
            "weak-md5",
            std::regex(R"(\bMD5\b|MD5_Init|md5\s*\()", std::regex::icase),
            "Algorithme MD5 détecté — collision connue depuis 2004",
            "CWE-327",
            "Utiliser SHA-256 ou SHA-3 pour le hachage",
            Severity::High, 7.5
        },
        {
            "weak-sha1",
            std::regex(R"(\bSHA1\b|SHA1_Init|sha1\s*\()", std::regex::icase),
            "Algorithme SHA-1 détecté — collision SHAttered (2017)",
            "CWE-327",
            "Utiliser SHA-256 ou SHA-3 à la place de SHA-1",
            Severity::High, 7.0
        },
        {
            "weak-des",
            std::regex(R"(\bDES_\w|\bEVP_des\b)", std::regex::icase),
            "Chiffrement DES détecté — clé 56 bits, cassable",
            "CWE-327",
            "Utiliser AES-256-GCM à la place de DES/3DES",
            Severity::High, 7.5
        },
        {
            "weak-rc4",
            std::regex(R"(\bRC4\b|RC4_set_key|EVP_rc4\b)", std::regex::icase),
            "Chiffrement RC4 détecté — biais statistiques exploitables",
            "CWE-327",
            "Utiliser AES-256-GCM ou ChaCha20-Poly1305",
            Severity::High, 7.5
        },
        {
            "hardcoded-secret",
            std::regex(R"((password|secret|api_key|apikey|token|passwd|pwd)\s*=\s*["'][^"']{4,}["'])",
                       std::regex::icase),
            "Secret potentiellement hardcodé dans le code source",
            "CWE-798",
            "Stocker les secrets dans des variables d'environnement ou un gestionnaire de secrets",
            Severity::Critical, 9.8
        },
        {
            "hardcoded-key",
            std::regex(R"((private_key|encryption_key|signing_key)\s*=\s*["'][^"']{8,}["'])",
                       std::regex::icase),
            "Clé cryptographique hardcodée dans le code",
            "CWE-321",
            "Générer les clés dynamiquement et les stocker hors du code source",
            Severity::Critical, 9.5
        },
        {
            "predictable-seed",
            std::regex(R"(srand\s*\(\s*time\s*\()", std::regex::icase),
            "Seed prévisible srand(time(0)) — ne pas utiliser pour la cryptographie",
            "CWE-338",
            "Utiliser /dev/urandom ou std::random_device pour les opérations crypto",
            Severity::Medium, 5.0
        },
        {
            "weak-ecb-mode",
            std::regex(R"(EVP_aes_\d+_ecb|AES_ECB|_ECB\b)", std::regex::icase),
            "Mode ECB détecté — révèle des patterns dans les données chiffrées",
            "CWE-327",
            "Utiliser le mode GCM ou CBC avec IV aléatoire",
            Severity::High, 7.0
        },
        {
            "cert-in-code",
            std::regex(R"(-----BEGIN (RSA |EC |DSA |CERTIFICATE|PRIVATE KEY))",
                       std::regex::icase),
            "Certificat ou clé privée dans le code source",
            "CWE-321",
            "Ne jamais committer des certificats — utiliser un gestionnaire de secrets",
            Severity::Critical, 9.5
        },
    };
    return rules;
}

bool isSourceFile(const std::filesystem::path &p)
{
    static const std::unordered_set<std::string> exts = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
        ".py", ".js", ".ts", ".php", ".java", ".go", ".rb",
        ".yaml", ".yml", ".toml", ".conf", ".ini", ".env"
    };
    std::string ext = p.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    if (exts.count(ext)) return true;
    // .env files without extension
    const auto name = p.filename().string();
    return name == ".env" || name == "config" || name == "secrets";
}

} // namespace

std::vector<Vulnerability> detectCryptoIssues(const std::filesystem::path &file)
{
    if (!isSourceFile(file)) return {};

    std::ifstream in(file);
    if (!in) return {};

    std::vector<Vulnerability> results;
    std::string line;
    std::size_t lineNum = 0;

    while (std::getline(in, line)) {
        ++lineNum;
        // Strip C-style line comments only (keep YAML/config as-is)
        std::string code = line;
        const auto slashPos = line.find("//");
        if (slashPos != std::string::npos) code = line.substr(0, slashPos);
        if (code.find_first_not_of(" \t") == std::string::npos) continue;

        for (const auto &rule : cryptoRules()) {
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
                v.category    = "crypto";
                results.push_back(std::move(v));
                break;
            }
        }
    }
    return results;
}

} // namespace analyzer
} // namespace episcan
