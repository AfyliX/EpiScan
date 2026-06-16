#include <gtest/gtest.h>
#include "analyzer/InjectionDetector.hpp"
#include "analyzer/CryptoDetector.hpp"
#include "analyzer/UnsafeFunctionDetector.hpp"
#include "analyzer/CodeParser.hpp"

#include <filesystem>
#include <fstream>
#include <string>

namespace {

std::filesystem::path writeTempFile(const std::string &name, const std::string &content)
{
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream f(path);
    f << content;
    return path;
}

} // namespace

// ── InjectionDetector ─────────────────────────────────────────────────────────

TEST(InjectionDetector, DetectsSqlConcatenation)
{
    const auto f = writeTempFile("sql_test.cpp", R"(
std::string q = "SELECT * FROM users WHERE id = " + user_input;
)");
    const auto findings = episcan::analyzer::detectInjections(f);
    EXPECT_FALSE(findings.empty());
    EXPECT_EQ(findings[0].category, "injection");
    std::filesystem::remove(f);
}

TEST(InjectionDetector, DetectsSystemConcatenation)
{
    const auto f = writeTempFile("cmd_test.cpp", R"(
system("ls " + user_dir);
)");
    const auto findings = episcan::analyzer::detectInjections(f);
    EXPECT_FALSE(findings.empty());
    EXPECT_EQ(findings[0].category, "injection");
    std::filesystem::remove(f);
}

TEST(InjectionDetector, CleanCodeProducesNoFindings)
{
    const auto f = writeTempFile("clean_sql.cpp", R"(
// Using prepared statement
stmt->setString(1, userId);
auto result = stmt->executeQuery();
)");
    const auto findings = episcan::analyzer::detectInjections(f);
    EXPECT_TRUE(findings.empty());
    std::filesystem::remove(f);
}

// ── CryptoDetector ────────────────────────────────────────────────────────────

TEST(CryptoDetector, DetectsMd5)
{
    const auto f = writeTempFile("md5_test.cpp", R"(
#include <openssl/md5.h>
MD5_CTX ctx;
MD5_Init(&ctx);
)");
    const auto findings = episcan::analyzer::detectCryptoIssues(f);
    EXPECT_FALSE(findings.empty());
    EXPECT_EQ(findings[0].category, "crypto");
    std::filesystem::remove(f);
}

TEST(CryptoDetector, DetectsHardcodedSecret)
{
    const auto f = writeTempFile("secret_test.cpp", R"(
const char* password = "super_secret_password_123";
)");
    const auto findings = episcan::analyzer::detectCryptoIssues(f);
    EXPECT_FALSE(findings.empty());
    EXPECT_EQ(findings[0].id, "hardcoded-secret");
    std::filesystem::remove(f);
}

TEST(CryptoDetector, DetectsPredictableSeed)
{
    const auto f = writeTempFile("rand_test.cpp", R"(
srand(time(0));
int x = rand();
)");
    const auto findings = episcan::analyzer::detectCryptoIssues(f);
    EXPECT_FALSE(findings.empty());
    EXPECT_EQ(findings[0].id, "predictable-seed");
    std::filesystem::remove(f);
}

TEST(CryptoDetector, CleanCryptoNoFindings)
{
    const auto f = writeTempFile("clean_crypto.cpp", R"(
std::random_device rd;
std::mt19937_64 gen(rd());
)");
    const auto findings = episcan::analyzer::detectCryptoIssues(f);
    EXPECT_TRUE(findings.empty());
    std::filesystem::remove(f);
}

// ── UnsafeFunctionDetector ────────────────────────────────────────────────────

TEST(UnsafeFunctionDetector, DetectsGets)
{
    const auto f = writeTempFile("gets_test.c", R"(
char buf[64];
gets(buf);
)");
    const auto findings = episcan::analyzer::detectUnsafeFunctions(f);
    EXPECT_FALSE(findings.empty());
    EXPECT_EQ(findings[0].category, "unsafe_func");
    std::filesystem::remove(f);
}

TEST(UnsafeFunctionDetector, DetectsStrcpy)
{
    const auto f = writeTempFile("strcpy_test.c", R"(
strcpy(dest, src);
)");
    const auto findings = episcan::analyzer::detectUnsafeFunctions(f);
    EXPECT_FALSE(findings.empty());
    std::filesystem::remove(f);
}

TEST(UnsafeFunctionDetector, DetectsSystemCall)
{
    const auto f = writeTempFile("system_test.c", R"(
system("rm -rf /tmp/old");
)");
    const auto findings = episcan::analyzer::detectUnsafeFunctions(f);
    EXPECT_FALSE(findings.empty());
    std::filesystem::remove(f);
}

TEST(UnsafeFunctionDetector, SkipsNonCFiles)
{
    const auto f = writeTempFile("test.py", R"(
gets(buf)  # Python, should not match C rules
)");
    const auto findings = episcan::analyzer::detectUnsafeFunctions(f);
    EXPECT_TRUE(findings.empty());
    std::filesystem::remove(f);
}

// ── CodeParser integration ────────────────────────────────────────────────────

TEST(CodeParser, AnalyzesDirectoryAndCountsFiles)
{
    const auto dir = std::filesystem::temp_directory_path() / "episcan_test_dir";
    std::filesystem::create_directories(dir);

    // Write a vulnerable file
    {
        std::ofstream f(dir / "vuln.c");
        f << "strcpy(dest, src);\n";
    }
    // Write a clean file
    {
        std::ofstream f(dir / "clean.cpp");
        f << "// nothing dangerous\n";
    }

    std::size_t scannedFiles = 0;
    const auto findings = episcan::analyzer::analyzeDirectory(dir, {}, &scannedFiles);
    EXPECT_GE(scannedFiles, 1u);
    EXPECT_FALSE(findings.empty());

    std::filesystem::remove_all(dir);
}
