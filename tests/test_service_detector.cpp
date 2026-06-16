#include <gtest/gtest.h>
#include "network/ServiceDetector.hpp"
#include "network/BannerGrabber.hpp"

TEST(ServiceDetector, WellKnownPortNames)
{
    EXPECT_EQ(episcan::network::wellKnownService(22),    "ssh");
    EXPECT_EQ(episcan::network::wellKnownService(80),    "http");
    EXPECT_EQ(episcan::network::wellKnownService(443),   "https");
    EXPECT_EQ(episcan::network::wellKnownService(3306),  "mysql");
    EXPECT_EQ(episcan::network::wellKnownService(6379),  "redis");
    EXPECT_EQ(episcan::network::wellKnownService(27017), "mongodb");
    EXPECT_EQ(episcan::network::wellKnownService(9999),  ""); // unknown
}

TEST(ServiceDetector, DetectServicesOnEmptyPortList)
{
    const auto services = episcan::network::detectServices("127.0.0.1", {}, 500);
    EXPECT_TRUE(services.empty());
}

TEST(ServiceDetector, DetectServicesDoesNotCrash)
{
    // Give a port that's likely closed — should still return a ServiceInfo
    const std::vector<uint16_t> ports = {9999};
    const auto services = episcan::network::detectServices("127.0.0.1", ports, 300);
    // Even if the banner grab fails, we should get one entry with wellKnown = ""
    EXPECT_EQ(services.size(), 1u);
    EXPECT_EQ(services[0].port, 9999u);
}

TEST(BannerGrabber, GrabClosedPortReturnsNotGrabbed)
{
    const auto result = episcan::network::grabBanner("127.0.0.1", 9991, 300);
    EXPECT_FALSE(result.grabbed);
    EXPECT_TRUE(result.banner.empty());
}

TEST(BannerGrabber, GrabInvalidHostReturnsNotGrabbed)
{
    const auto result = episcan::network::grabBanner("invalid.host.does.not.exist", 80, 300);
    EXPECT_FALSE(result.grabbed);
}
