#include <gtest/gtest.h>
#include "analyzer/CodeParser.hpp"
#include "core/Report.hpp"
#include "core/Metrics.hpp"
#include "core/Cvss.hpp"

#include <filesystem>
#include <fstream>
#include <string>

namespace {

std::filesystem::path makeSampleProject()
{
    const auto dir = std::filesystem::temp_directory_path() / "episcan_integration";
    std::filesystem::create_directories(dir);

    // File with multiple vulnerability types
    {
        std::ofstream f(dir / "app.c");
        f << R"(
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>

/* Auth module */
const char* DB_PASSWORD = "hardcoded_password_1234";

void processInput(char* user_input) {
    char buf[64];
    strcpy(buf, user_input);   // unsafe
    gets(buf);                  // unsafe

    MD5_CTX ctx;               // weak crypto
    MD5_Init(&ctx);

    // SQL injection
    char query[256];
    sprintf(query, "SELECT * FROM users WHERE name = '%s'", user_input);

    char* data = malloc(1024);  // no null check
    system("ls " + 0);         // command injection
}
)";
    }

    // Clean file — should produce minimal findings
    {
        std::ofstream f(dir / "clean.cpp");
        f << R"(
#include <vector>
#include <string>

void safe_function(const std::string& input) {
    std::vector<char> buf(input.begin(), input.end());
    // Using prepared statement
    // stmt->setString(1, input);
}
)";
    }

    return dir;
}

} // namespace

// ── End-to-end: scan directory → report ──────────────────────────────────────

TEST(Integration, ScanAndProduceJsonReport)
{
    const auto dir = makeSampleProject();
    const auto reportPath = std::filesystem::temp_directory_path() / "episcan_test_report.json";

    std::size_t scannedFiles = 0;
    const auto findings = episcan::analyzer::analyzeDirectory(dir, {}, &scannedFiles);

    EXPECT_GE(scannedFiles, 1u);
    EXPECT_FALSE(findings.empty()) << "Expected findings in vulnerable sample";

    const auto report = episcan::buildReport(dir.string(), findings, scannedFiles, 0, 1.5);
    EXPECT_EQ(report.findings.size(), findings.size());
    EXPECT_GT(report.summary.total, 0u);

    episcan::writeReportJson(reportPath, report);
    EXPECT_TRUE(std::filesystem::exists(reportPath));
    EXPECT_GT(std::filesystem::file_size(reportPath), 10u);

    std::filesystem::remove(reportPath);
    std::filesystem::remove_all(dir);
}

TEST(Integration, ScanAndProduceHtmlReport)
{
    const auto dir = makeSampleProject();
    const auto reportPath = std::filesystem::temp_directory_path() / "episcan_test_report.html";

    std::size_t scannedFiles = 0;
    const auto findings = episcan::analyzer::analyzeDirectory(dir, {}, &scannedFiles);
    const auto report = episcan::buildReport(dir.string(), findings, scannedFiles, 0, 1.0);

    episcan::writeReportHtml(reportPath, report);
    EXPECT_TRUE(std::filesystem::exists(reportPath));

    // Verify it's valid HTML (contains key tags)
    std::ifstream f(reportPath);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    EXPECT_NE(content.find("<!DOCTYPE html>"), std::string::npos);
    EXPECT_NE(content.find("EpiScan"), std::string::npos);

    std::filesystem::remove(reportPath);
    std::filesystem::remove_all(dir);
}

TEST(Integration, ScanAndProduceMarkdownReport)
{
    const auto dir = makeSampleProject();
    const auto reportPath = std::filesystem::temp_directory_path() / "episcan_test_report.md";

    std::size_t scannedFiles = 0;
    const auto findings = episcan::analyzer::analyzeDirectory(dir, {}, &scannedFiles);
    const auto report = episcan::buildReport(dir.string(), findings, scannedFiles, 0, 1.0);

    episcan::writeReportMarkdown(reportPath, report);
    EXPECT_TRUE(std::filesystem::exists(reportPath));

    std::ifstream f(reportPath);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    EXPECT_NE(content.find("# EpiScan"), std::string::npos);

    std::filesystem::remove(reportPath);
    std::filesystem::remove_all(dir);
}

// ── CVSS v3.1 scoring (#83) ──────────────────────────────────────────────────

TEST(Cvss31, KnownVector_9_8)
{
    // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
    episcan::CvssVector v;
    v.av = episcan::CvssVector::AV::Network;
    v.ac = episcan::CvssVector::AC::Low;
    v.pr = episcan::CvssVector::PR::None;
    v.ui = episcan::CvssVector::UI::None;
    v.s  = episcan::CvssVector::S::Unchanged;
    v.c  = episcan::CvssVector::I::High;
    v.i  = episcan::CvssVector::I::High;
    v.a  = episcan::CvssVector::I::High;

    const double score = episcan::computeCvss31(v);
    EXPECT_NEAR(score, 9.8, 0.1);
}

TEST(Cvss31, ParseVectorString)
{
    const auto v = episcan::parseCvssVector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    EXPECT_EQ(v.av, episcan::CvssVector::AV::Network);
    EXPECT_EQ(v.ac, episcan::CvssVector::AC::Low);
    EXPECT_EQ(v.c,  episcan::CvssVector::I::High);

    const double score = episcan::computeCvss31(v);
    EXPECT_NEAR(score, 9.8, 0.1);
}

TEST(Cvss31, CvssForInjectionCategory)
{
    const auto v = episcan::cvssForCategory("injection");
    const double score = episcan::computeCvss31(v);
    EXPECT_GE(score, 9.0);
}

TEST(Cvss31, CvssForCryptoCategory)
{
    const auto v = episcan::cvssForCategory("crypto");
    const double score = episcan::computeCvss31(v);
    EXPECT_GE(score, 5.0);
    EXPECT_LE(score, 7.0);
}

// ── Metrics (#85) ────────────────────────────────────────────────────────────

TEST(Metrics, ComputesSecurityScore)
{
    std::vector<episcan::Vulnerability> findings;
    episcan::Vulnerability v;
    v.severity = episcan::Severity::Critical;
    v.category = "injection";
    findings.push_back(v);

    const auto m = episcan::computeMetrics(findings, 10, 100, 5.0);
    EXPECT_LT(m.securityScore, 100.0);
    EXPECT_EQ(m.totalFindings, 1u);
    EXPECT_EQ(m.countByCategory.at("injection"), 1u);
    EXPECT_EQ(m.countBySeverity.at("critical"), 1u);
}

TEST(Metrics, EmptyFindingsMaxScore)
{
    const auto m = episcan::computeMetrics({}, 5, 50, 1.0);
    EXPECT_NEAR(m.securityScore, 100.0, 0.01);
    EXPECT_EQ(m.totalFindings, 0u);
    EXPECT_NEAR(m.avgCvss, 0.0, 0.01);
}
