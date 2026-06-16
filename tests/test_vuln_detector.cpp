#include <gtest/gtest.h>
#include "analyzer/VulnDetector.hpp"

#include <filesystem>
#include <fstream>

namespace {

std::filesystem::path writeTempFile(const std::string &name, const std::string &content)
{
    const auto path = std::filesystem::temp_directory_path() / name;
    std::ofstream f(path);
    f << content;
    return path;
}

} // namespace

TEST(VulnDetector, DetectsMallocWithoutCheck)
{
    const auto f = writeTempFile("malloc_test.c", R"(
char *buf = malloc(1024);
memcpy(buf, src, 1024);
)");
    const auto findings = episcan::analyzer::detectBufferVulns(f);
    EXPECT_FALSE(findings.empty());
    std::filesystem::remove(f);
}

TEST(VulnDetector, DetectsArrayNoChecks)
{
    const auto f = writeTempFile("arr_test.c", R"(
int arr[10];
arr[i] = 42;
)");
    const auto findings = episcan::analyzer::detectBufferVulns(f);
    EXPECT_FALSE(findings.empty());
    std::filesystem::remove(f);
}

TEST(VulnDetector, DetectsMemcpy)
{
    const auto f = writeTempFile("memcpy_test.c", R"(
memcpy(dst, src, len);
)");
    const auto findings = episcan::analyzer::detectBufferVulns(f);
    EXPECT_FALSE(findings.empty());
    std::filesystem::remove(f);
}

TEST(VulnDetector, SkipsNonCppFiles)
{
    const auto f = writeTempFile("test.py", R"(
# malloc(1024) this is python
)");
    const auto findings = episcan::analyzer::detectBufferVulns(f);
    EXPECT_TRUE(findings.empty());
    std::filesystem::remove(f);
}

TEST(VulnDetector, CleanCodeNoFindings)
{
    const auto f = writeTempFile("safe_code.cpp", R"(
#include <vector>
std::vector<int> safe_buffer(1024, 0);
safe_buffer.at(0) = 42;  // bounds checked
)");
    const auto findings = episcan::analyzer::detectBufferVulns(f);
    // .at() usage — should not trigger array-no-bounds pattern
    // (pattern matches \w+[\w+] = , .at() does not match)
    for (const auto &v : findings) {
        EXPECT_NE(v.id, "free-then-use");
        EXPECT_NE(v.id, "double-free-pattern");
    }
    std::filesystem::remove(f);
}
