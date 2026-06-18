#include "app/ScannerEngine.hpp"
#include "network/NetworkvulAnalyzer.hpp"
#include "core/Report.hpp"
#include "core/Severity.hpp"

#ifdef EPISCAN_HAVE_PCAP
#include "network/TrafficAnalyzer.hpp"
#endif

#include <SFML/Graphics.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

enum class Tab { Code, Network, Traffic };

enum class PickerKind { None, Path, Interface };

struct Button {
    sf::FloatRect bounds;
    std::string label;
};

bool pointInRect(const sf::Vector2f &point, const sf::FloatRect &rect)
{
    return rect.contains(point);
}

std::string truncateMiddle(const std::string &value, std::size_t maxLen)
{
    if (value.size() <= maxLen || maxLen < 8) {
        return value;
    }
    const std::size_t left = (maxLen - 3) / 2;
    const std::size_t right = maxLen - 3 - left;
    return value.substr(0, left) + "..." + value.substr(value.size() - right);
}

int parseIntOr(const std::string &value, int fallback)
{
    try {
        return std::stoi(value);
    } catch (...) {
        return fallback;
    }
}

void drawText(sf::RenderWindow &window, const sf::Font &font,
    const std::string &value, unsigned int size,
    float x, float y, const sf::Color &color)
{
    sf::Text text;
    text.setFont(font);
    text.setCharacterSize(size);
    text.setFillColor(color);
    text.setString(value);
    text.setPosition(x, y);
    window.draw(text);
}

bool loadUiFont(sf::Font &font)
{
    const std::vector<std::string> candidates = {
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"
    };

    for (const auto &path : candidates) {
        if (font.loadFromFile(path)) {
            return true;
        }
    }
    return false;
}

sf::Color severityColor(const std::string &severity)
{
    if (severity == "critical" || severity == "Critical") return sf::Color(220, 60, 60);
    if (severity == "high" || severity == "High") return sf::Color(230, 140, 50);
    if (severity == "medium" || severity == "Medium") return sf::Color(220, 200, 60);
    return sf::Color(150, 160, 175);
}

// ── Code scan state ──────────────────────────────────────────────────────────

struct CodeState {
    std::mutex mutex;
    bool scanning = false;
    bool hasResult = false;
    std::size_t processed = 0;
    std::size_t total = 0;
    std::filesystem::path current;
    std::string status = "Ready";
    episcan::ScanResult result;
    std::filesystem::path reportPath;
};

// ── Network (port/service/SSL) scan state ───────────────────────────────────

struct NetworkState {
    std::mutex mutex;
    bool scanning = false;
    bool hasResult = false;
    std::string status = "Ready";
    episcan::network::NetworkScanResult result;
};

// ── Traffic capture state ───────────────────────────────────────────────────

#ifdef EPISCAN_HAVE_PCAP
struct TrafficState {
    std::mutex mutex;
    bool running = false;
    bool hasResult = false;
    std::size_t packets = 0;
    std::size_t findingsCount = 0;
    std::string status = "Ready";
    std::vector<episcan::network::PacketFinding> findings;
};
#endif

} // namespace

int main()
{
    sf::RenderWindow window(sf::VideoMode(1100, 760), "EpiScan - SFML Security Scanner",
        sf::Style::Titlebar | sf::Style::Close);
    window.setFramerateLimit(60);

    sf::Font font;
    if (!loadUiFont(font)) {
        return 1;
    }

    // ── Tab bar ──────────────────────────────────────────────────────────────
    const Button codeTabButton {{20.f, 16.f, 200.f, 38.f}, "Code Scan"};
    const Button networkTabButton {{230.f, 16.f, 200.f, 38.f}, "Network Scan"};
    const Button trafficTabButton {{440.f, 16.f, 220.f, 38.f}, "Traffic Capture"};
    Tab activeTab = Tab::Code;

    enum class ActiveField {
        None,
        CodeTarget,
        CodeReport,
        NetTarget,
        NetPortStart,
        NetPortEnd,
        NetReport,
        TrafficIface,
        TrafficPcap,
        TrafficDuration,
        TrafficReport
    };
    ActiveField activeField = ActiveField::None;

    // ── Code scan tab ────────────────────────────────────────────────────────

    std::string codeTargetInput = std::filesystem::current_path().string();
    std::string codeReportInput = (std::filesystem::current_path() / "report_gui.json").string();

    const sf::FloatRect codeTargetField(20.f, 138.f, 950.f, 40.f);
    const Button browseTargetButton {{980.f, 138.f, 100.f, 40.f}, "Browse"};
    const sf::FloatRect codeReportField(20.f, 213.f, 950.f, 40.f);
    const Button browseReportButton {{980.f, 213.f, 100.f, 40.f}, "Browse"};
    const Button scanTargetButton {{20.f, 273.f, 260.f, 44.f}, "Scan Target"};
    const Button scanAllButton {{300.f, 273.f, 260.f, 44.f}, "Scan All System"};

    CodeState codeShared;
    std::thread codeThread;

    auto startCodeScan = [&](bool allSystem) {
        std::lock_guard<std::mutex> lock(codeShared.mutex);
        if (codeShared.scanning) {
            return;
        }

        codeShared.scanning = true;
        codeShared.hasResult = false;
        codeShared.processed = 0;
        codeShared.total = 0;
        codeShared.current.clear();
        codeShared.status = allSystem ? "Scanning all system..." : "Scanning target...";

        const std::filesystem::path targetPath = allSystem ? std::filesystem::path("/") : std::filesystem::path(codeTargetInput);
        const std::filesystem::path reportPath = std::filesystem::path(codeReportInput);

        if (codeThread.joinable()) {
            codeThread.join();
        }

        codeThread = std::thread([&, targetPath, reportPath, allSystem]() {
            try {
                episcan::ScanOptions options;
                options.codePath = targetPath;
                options.reportPath = reportPath;
                options.scanAllSystem = allSystem;

                auto result = episcan::runScan(options, [&](const episcan::ScanProgress &progress) {
                    std::lock_guard<std::mutex> progressLock(codeShared.mutex);
                    codeShared.processed = progress.processedFiles;
                    codeShared.total = progress.totalFiles;
                    codeShared.current = progress.currentFile;
                });

                auto report = episcan::buildReport(targetPath.string(), result.findings,
                    result.scannedFiles, 0, result.durationSec);
                episcan::applyPreviousScanDelta(report, reportPath);
                episcan::writeReportAuto(reportPath, report);

                std::lock_guard<std::mutex> doneLock(codeShared.mutex);
                codeShared.result = std::move(result);
                codeShared.hasResult = true;
                codeShared.scanning = false;
                codeShared.reportPath = reportPath;
                codeShared.status = "Scan completed";
            } catch (const std::exception &error) {
                std::lock_guard<std::mutex> errorLock(codeShared.mutex);
                codeShared.scanning = false;
                codeShared.hasResult = false;
                codeShared.status = std::string("Error: ") + error.what();
            }
        });
    };

    // ── Network scan tab ─────────────────────────────────────────────────────

    std::string netTargetInput = "127.0.0.1";
    std::string netPortStartInput = "1";
    std::string netPortEndInput = "1024";
    std::string netReportInput = (std::filesystem::current_path() / "network_report.json").string();

    const sf::FloatRect netTargetField(20.f, 138.f, 1060.f, 40.f);
    const sf::FloatRect netPortStartField(20.f, 213.f, 510.f, 40.f);
    const sf::FloatRect netPortEndField(570.f, 213.f, 510.f, 40.f);
    const sf::FloatRect netReportField(20.f, 288.f, 950.f, 40.f);
    const Button browseNetReportButton {{980.f, 288.f, 100.f, 40.f}, "Browse"};
    const Button scanNetworkButton {{20.f, 348.f, 260.f, 44.f}, "Scan Network"};

    NetworkState netShared;
    std::thread netThread;

    auto startNetworkScan = [&]() {
        std::lock_guard<std::mutex> lock(netShared.mutex);
        if (netShared.scanning) {
            return;
        }

        netShared.scanning = true;
        netShared.hasResult = false;
        netShared.status = "Scanning network...";

        const std::string target = netTargetInput;
        const uint16_t portStart = static_cast<uint16_t>(std::clamp(parseIntOr(netPortStartInput, 1), 1, 65535));
        const uint16_t portEnd = static_cast<uint16_t>(std::clamp(parseIntOr(netPortEndInput, 1024), 1, 65535));
        const std::filesystem::path reportPath = std::filesystem::path(netReportInput);

        if (netThread.joinable()) {
            netThread.join();
        }

        netThread = std::thread([&, target, portStart, portEnd, reportPath]() {
            try {
                episcan::network::NetworkScanOptions options;
                options.target = target;
                options.portStart = portStart;
                options.portEnd = portEnd;
                options.sslAudit = true;

                const auto scanStart = std::chrono::steady_clock::now();
                auto result = episcan::network::analyzeNetwork(options);
                const double durationSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - scanStart).count();

                auto report = episcan::buildReport(target, result.findings, 0, result.scannedPorts, durationSec);
                episcan::applyPreviousScanDelta(report, reportPath);
                episcan::writeReportAuto(reportPath, report);

                std::lock_guard<std::mutex> doneLock(netShared.mutex);
                netShared.result = std::move(result);
                netShared.hasResult = true;
                netShared.scanning = false;
                netShared.status = "Network scan completed — report: " + reportPath.string();
            } catch (const std::exception &error) {
                std::lock_guard<std::mutex> errorLock(netShared.mutex);
                netShared.scanning = false;
                netShared.hasResult = false;
                netShared.status = std::string("Error: ") + error.what();
            }
        });
    };

    // ── Traffic capture tab ──────────────────────────────────────────────────

    std::string trafficIfaceInput = "any";
    std::string trafficPcapInput;
    std::string trafficDurationInput = "30";
    std::string trafficReportInput = (std::filesystem::current_path() / "traffic_report.json").string();

#ifdef EPISCAN_HAVE_PCAP
    const sf::FloatRect trafficIfaceField(20.f, 138.f, 420.f, 40.f);
    const Button browseIfaceButton {{450.f, 138.f, 90.f, 40.f}, "Select"};
    const sf::FloatRect trafficDurationField(570.f, 138.f, 510.f, 40.f);
    const sf::FloatRect trafficPcapField(20.f, 213.f, 950.f, 40.f);
    const Button browsePcapButton {{980.f, 213.f, 100.f, 40.f}, "Browse"};
    const sf::FloatRect trafficReportField(20.f, 288.f, 950.f, 40.f);
    const Button browseTrafficReportButton {{980.f, 288.f, 100.f, 40.f}, "Browse"};
    const Button captureLiveButton {{20.f, 348.f, 260.f, 44.f}, "Capture Live"};
    const Button analyzePcapButton {{300.f, 348.f, 260.f, 44.f}, "Analyze Pcap"};

    TrafficState trafficShared;
    std::thread trafficThread;

    auto startTrafficCapture = [&](bool live) {
        std::lock_guard<std::mutex> lock(trafficShared.mutex);
        if (trafficShared.running) {
            return;
        }

        trafficShared.running = true;
        trafficShared.hasResult = false;
        trafficShared.packets = 0;
        trafficShared.findingsCount = 0;
        trafficShared.status = live ? "Capturing live traffic..." : "Analyzing pcap file...";

        const std::string iface = trafficIfaceInput;
        const std::string pcapFile = live ? std::string() : trafficPcapInput;
        const int duration = std::max(1, parseIntOr(trafficDurationInput, 30));
        const std::filesystem::path reportPath = std::filesystem::path(trafficReportInput);

        if (trafficThread.joinable()) {
            trafficThread.join();
        }

        trafficThread = std::thread([&, iface, pcapFile, duration, reportPath]() {
            try {
                episcan::network::TrafficScanOptions options;
                options.interface = iface;
                options.pcapFile = pcapFile;
                options.durationSeconds = duration;
                options.reportPath = reportPath;

                auto findings = episcan::network::analyzeTraffic(options,
                    [&](std::size_t packetsSeen, std::size_t findingsSoFar) {
                        std::lock_guard<std::mutex> progressLock(trafficShared.mutex);
                        trafficShared.packets = packetsSeen;
                        trafficShared.findingsCount = findingsSoFar;
                    });

                episcan::network::writeTrafficReport(reportPath, findings);

                std::lock_guard<std::mutex> doneLock(trafficShared.mutex);
                trafficShared.findings = std::move(findings);
                trafficShared.hasResult = true;
                trafficShared.running = false;
                trafficShared.status = "Capture completed";
            } catch (const std::exception &error) {
                std::lock_guard<std::mutex> errorLock(trafficShared.mutex);
                trafficShared.running = false;
                trafficShared.hasResult = false;
                std::string message = error.what();
                if (message.find("permission") != std::string::npos
                    || message.find("Permission") != std::string::npos
                    || message.find("CAP_NET_RAW") != std::string::npos) {
                    message += " - run 'sudo setcap cap_net_raw,cap_net_admin=eip <path-to-episcan>' once, or relaunch EpiScan with sudo.";
                }
                trafficShared.status = "Error: " + message;
            }
        });
    };
#endif

    // ── Scrollable picker overlay (folders, files, network interfaces) ─────────

    struct PickerState {
        bool open = false;
        PickerKind kind = PickerKind::None;
        std::string title;
        std::filesystem::path currentDir;
        std::vector<std::filesystem::path> dirEntries;
        std::vector<std::string> interfaceEntries;
        int scrollOffset = 0;
        std::string *target = nullptr;
        bool allowUseFolder = false;
        bool appendFilenameOnFolder = false;
        std::string suggestedFilename;
    };
    PickerState picker;

    const sf::FloatRect pickerPanel(150.f, 110.f, 800.f, 540.f);
    const sf::FloatRect pickerListArea(170.f, 200.f, 760.f, 380.f);
    constexpr float pickerRowHeight = 24.f;
    const int pickerVisibleRows = static_cast<int>(pickerListArea.height / pickerRowHeight);
    const Button pickerCloseButton {{pickerPanel.left + pickerPanel.width - 44.f, pickerPanel.top + 8.f, 34.f, 30.f}, "X"};
    const Button pickerUpButton {{pickerListArea.left, 160.f, 70.f, 32.f}, "Up"};
    const Button pickerHomeButton {{pickerListArea.left + 78.f, 160.f, 70.f, 32.f}, "Home"};
    const Button pickerUseFolderButton {{pickerListArea.left + 156.f, 160.f, 220.f, 32.f}, "Use this folder"};

    auto pickerEntryCount = [&]() {
        return picker.kind == PickerKind::Interface
            ? picker.interfaceEntries.size()
            : picker.dirEntries.size();
    };

    auto refreshPickerEntries = [&]() {
        picker.dirEntries.clear();
        std::error_code listError;
        for (const auto &entry : std::filesystem::directory_iterator(picker.currentDir, listError)) {
            picker.dirEntries.push_back(entry.path());
        }
        std::sort(picker.dirEntries.begin(), picker.dirEntries.end(), [](const auto &a, const auto &b) {
            std::error_code ecA, ecB;
            const bool dirA = std::filesystem::is_directory(a, ecA);
            const bool dirB = std::filesystem::is_directory(b, ecB);
            if (dirA != dirB) {
                return dirA;
            }
            return a.filename().string() < b.filename().string();
        });
        picker.scrollOffset = 0;
    };

    auto homeDirectory = [&]() {
        const char *home = std::getenv("HOME");
        return (home && std::filesystem::is_directory(home))
            ? std::filesystem::path(home)
            : std::filesystem::current_path();
    };

    auto openPathPicker = [&](std::string *target, const std::filesystem::path &startPath,
                              const std::string &title, bool allowUseFolder, bool appendFilenameOnFolder = false) {
        picker.open = true;
        picker.kind = PickerKind::Path;
        picker.title = title;
        picker.target = target;
        picker.allowUseFolder = allowUseFolder;
        picker.appendFilenameOnFolder = appendFilenameOnFolder;
        picker.suggestedFilename = appendFilenameOnFolder ? startPath.filename().string() : std::string();
        if (std::filesystem::is_directory(startPath)) {
            picker.currentDir = startPath;
        } else if (startPath.has_parent_path() && std::filesystem::is_directory(startPath.parent_path())) {
            picker.currentDir = startPath.parent_path();
        } else {
            picker.currentDir = std::filesystem::current_path();
        }
        refreshPickerEntries();
    };

#ifdef EPISCAN_HAVE_PCAP
    auto openInterfacePicker = [&](std::string *target) {
        picker.open = true;
        picker.kind = PickerKind::Interface;
        picker.title = "Select a network interface";
        picker.target = target;
        picker.interfaceEntries = episcan::network::listInterfaces();
        picker.scrollOffset = 0;
    };
#endif

    auto handlePickerClick = [&](const sf::Vector2f &mouse) {
        if (pointInRect(mouse, pickerCloseButton.bounds)) {
            picker.open = false;
            return;
        }

        if (picker.kind != PickerKind::Interface) {
            if (pointInRect(mouse, pickerUpButton.bounds)) {
                if (picker.currentDir.has_parent_path() && picker.currentDir != picker.currentDir.parent_path()) {
                    picker.currentDir = picker.currentDir.parent_path();
                    refreshPickerEntries();
                }
                return;
            }
            if (pointInRect(mouse, pickerHomeButton.bounds)) {
                picker.currentDir = homeDirectory();
                refreshPickerEntries();
                return;
            }
            if (picker.allowUseFolder && pointInRect(mouse, pickerUseFolderButton.bounds)) {
                if (picker.target) {
                    *picker.target = picker.appendFilenameOnFolder && !picker.suggestedFilename.empty()
                        ? (picker.currentDir / picker.suggestedFilename).string()
                        : picker.currentDir.string();
                }
                picker.open = false;
                return;
            }
        }

        const std::size_t total = pickerEntryCount();
        for (int row = 0; row < pickerVisibleRows; ++row) {
            const std::size_t index = static_cast<std::size_t>(picker.scrollOffset) + static_cast<std::size_t>(row);
            if (index >= total) {
                break;
            }

            const sf::FloatRect rowRect(pickerListArea.left, pickerListArea.top + static_cast<float>(row) * pickerRowHeight,
                pickerListArea.width, pickerRowHeight);
            if (!pointInRect(mouse, rowRect)) {
                continue;
            }

            if (picker.kind == PickerKind::Interface) {
                if (picker.target) {
                    *picker.target = picker.interfaceEntries[index];
                }
                picker.open = false;
            } else {
                const auto &entryPath = picker.dirEntries[index];
                std::error_code isDirError;
                if (std::filesystem::is_directory(entryPath, isDirError)) {
                    picker.currentDir = entryPath;
                    refreshPickerEntries();
                } else {
                    if (picker.target) {
                        *picker.target = entryPath.string();
                    }
                    picker.open = false;
                }
            }
            return;
        }
    };

    auto drawTabBar = [&]() {
        auto drawTab = [&](const Button &button, bool selected) {
            sf::RectangleShape shape(sf::Vector2f(button.bounds.width, button.bounds.height));
            shape.setPosition(button.bounds.left, button.bounds.top);
            shape.setFillColor(selected ? sf::Color(45, 125, 190) : sf::Color(34, 40, 50));
            shape.setOutlineThickness(1.f);
            shape.setOutlineColor(sf::Color(90, 95, 110));
            window.draw(shape);
            drawText(window, font, button.label, 17, button.bounds.left + 16.f, button.bounds.top + 9.f, sf::Color::White);
        };
        drawTab(codeTabButton, activeTab == Tab::Code);
        drawTab(networkTabButton, activeTab == Tab::Network);
        drawTab(trafficTabButton, activeTab == Tab::Traffic);
    };

    auto drawInput = [&](const sf::FloatRect &rect, const std::string &value, bool selected) {
        sf::RectangleShape box(sf::Vector2f(rect.width, rect.height));
        box.setPosition(rect.left, rect.top);
        box.setFillColor(sf::Color(28, 34, 43));
        box.setOutlineThickness(2.f);
        box.setOutlineColor(selected ? sf::Color(86, 166, 255) : sf::Color(70, 78, 90));
        window.draw(box);
        drawText(window, font, truncateMiddle(value, 150), 17, rect.left + 10.f, rect.top + 8.f, sf::Color(235, 240, 245));
    };

    auto drawButton = [&](const Button &button, const sf::Color &color) {
        sf::RectangleShape shape(sf::Vector2f(button.bounds.width, button.bounds.height));
        shape.setPosition(button.bounds.left, button.bounds.top);
        shape.setFillColor(color);
        shape.setOutlineThickness(1.f);
        shape.setOutlineColor(sf::Color(90, 95, 110));
        window.draw(shape);
        drawText(window, font, button.label, 18, button.bounds.left + 20.f, button.bounds.top + 10.f, sf::Color::White);
    };

    auto drawPicker = [&]() {
        if (!picker.open) {
            return;
        }

        sf::RectangleShape backdrop(sf::Vector2f(1100.f, 760.f));
        backdrop.setFillColor(sf::Color(0, 0, 0, 160));
        window.draw(backdrop);

        sf::RectangleShape panel(sf::Vector2f(pickerPanel.width, pickerPanel.height));
        panel.setPosition(pickerPanel.left, pickerPanel.top);
        panel.setFillColor(sf::Color(26, 30, 38));
        panel.setOutlineThickness(2.f);
        panel.setOutlineColor(sf::Color(90, 95, 110));
        window.draw(panel);

        drawText(window, font, picker.title, 18, pickerPanel.left + 16.f, pickerPanel.top + 10.f, sf::Color(230, 235, 240));
        drawButton(pickerCloseButton, sf::Color(130, 55, 55));

        if (picker.kind != PickerKind::Interface) {
            drawButton(pickerUpButton, sf::Color(60, 70, 85));
            drawButton(pickerHomeButton, sf::Color(60, 70, 85));
            const float textX = picker.allowUseFolder
                ? pickerUseFolderButton.bounds.left + pickerUseFolderButton.bounds.width + 16.f
                : pickerHomeButton.bounds.left + pickerHomeButton.bounds.width + 16.f;
            drawText(window, font, truncateMiddle(picker.currentDir.string(), 70), 14,
                textX, pickerUpButton.bounds.top + 8.f, sf::Color(200, 210, 224));
            if (picker.allowUseFolder) {
                drawButton(pickerUseFolderButton, sf::Color(45, 125, 190));
            }
        }

        const std::size_t total = pickerEntryCount();
        for (int row = 0; row < pickerVisibleRows; ++row) {
            const std::size_t index = static_cast<std::size_t>(picker.scrollOffset) + static_cast<std::size_t>(row);
            if (index >= total) {
                break;
            }

            const sf::FloatRect rowRect(pickerListArea.left, pickerListArea.top + static_cast<float>(row) * pickerRowHeight,
                pickerListArea.width, pickerRowHeight);
            sf::RectangleShape rowBg(sf::Vector2f(rowRect.width, rowRect.height - 2.f));
            rowBg.setPosition(rowRect.left, rowRect.top);
            rowBg.setFillColor(row % 2 == 0 ? sf::Color(32, 38, 48) : sf::Color(28, 34, 43));
            window.draw(rowBg);

            std::string label;
            sf::Color color(210, 215, 225);
            if (picker.kind == PickerKind::Interface) {
                label = picker.interfaceEntries[index];
            } else {
                const auto &entryPath = picker.dirEntries[index];
                std::error_code isDirError;
                const bool isDir = std::filesystem::is_directory(entryPath, isDirError);
                label = (isDir ? std::string("[DIR] ") : std::string("      ")) + entryPath.filename().string();
            }
            drawText(window, font, truncateMiddle(label, 110), 14, rowRect.left + 8.f, rowRect.top + 3.f, color);
        }

        if (total > static_cast<std::size_t>(pickerVisibleRows)) {
            const std::size_t shown = std::min(total, static_cast<std::size_t>(picker.scrollOffset) + static_cast<std::size_t>(pickerVisibleRows));
            drawText(window, font,
                std::to_string(picker.scrollOffset + 1) + "-" + std::to_string(shown) + " / " + std::to_string(total) + " (scroll to see more)",
                13, pickerListArea.left, pickerListArea.top + pickerListArea.height + 6.f, sf::Color(150, 160, 175));
        }
    };

    while (window.isOpen()) {
        sf::Event event;
        while (window.pollEvent(event)) {
            if (event.type == sf::Event::Closed) {
                window.close();
            }

            if (event.type == sf::Event::Resized) {
                window.setView(sf::View(sf::FloatRect(0.f, 0.f,
                    static_cast<float>(event.size.width), static_cast<float>(event.size.height))));
            }

            if (event.type == sf::Event::MouseWheelScrolled && picker.open) {
                const std::size_t total = pickerEntryCount();
                const int maxOffset = std::max(0, static_cast<int>(total) - pickerVisibleRows);
                picker.scrollOffset = std::clamp(
                    picker.scrollOffset - static_cast<int>(event.mouseWheelScroll.delta) * 2,
                    0, maxOffset);
            }

            if (event.type == sf::Event::MouseButtonPressed && event.mouseButton.button == sf::Mouse::Left) {
                const sf::Vector2f mouse(static_cast<float>(event.mouseButton.x), static_cast<float>(event.mouseButton.y));

                if (picker.open) {
                    handlePickerClick(mouse);
                } else if (pointInRect(mouse, codeTabButton.bounds)) {
                    activeTab = Tab::Code;
                    activeField = ActiveField::None;
                } else if (pointInRect(mouse, networkTabButton.bounds)) {
                    activeTab = Tab::Network;
                    activeField = ActiveField::None;
                } else if (pointInRect(mouse, trafficTabButton.bounds)) {
                    activeTab = Tab::Traffic;
                    activeField = ActiveField::None;
                } else if (activeTab == Tab::Code) {
                    if (pointInRect(mouse, codeTargetField)) {
                        activeField = ActiveField::CodeTarget;
                    } else if (pointInRect(mouse, codeReportField)) {
                        activeField = ActiveField::CodeReport;
                    } else {
                        activeField = ActiveField::None;
                    }

                    if (pointInRect(mouse, browseTargetButton.bounds)) {
                        openPathPicker(&codeTargetInput, codeTargetInput, "Select a file or folder to scan", true);
                    }
                    if (pointInRect(mouse, browseReportButton.bounds)) {
                        openPathPicker(&codeReportInput, codeReportInput, "Select report output location", true, true);
                    }
                    if (pointInRect(mouse, scanTargetButton.bounds)) {
                        startCodeScan(false);
                    }
                    if (pointInRect(mouse, scanAllButton.bounds)) {
                        startCodeScan(true);
                    }
                } else if (activeTab == Tab::Network) {
                    if (pointInRect(mouse, netTargetField)) {
                        activeField = ActiveField::NetTarget;
                    } else if (pointInRect(mouse, netPortStartField)) {
                        activeField = ActiveField::NetPortStart;
                    } else if (pointInRect(mouse, netPortEndField)) {
                        activeField = ActiveField::NetPortEnd;
                    } else if (pointInRect(mouse, netReportField)) {
                        activeField = ActiveField::NetReport;
                    } else {
                        activeField = ActiveField::None;
                    }

                    if (pointInRect(mouse, browseNetReportButton.bounds)) {
                        openPathPicker(&netReportInput, netReportInput, "Select report output location", true, true);
                    }
                    if (pointInRect(mouse, scanNetworkButton.bounds)) {
                        startNetworkScan();
                    }
                } else if (activeTab == Tab::Traffic) {
#ifdef EPISCAN_HAVE_PCAP
                    if (pointInRect(mouse, trafficIfaceField)) {
                        activeField = ActiveField::TrafficIface;
                    } else if (pointInRect(mouse, trafficDurationField)) {
                        activeField = ActiveField::TrafficDuration;
                    } else if (pointInRect(mouse, trafficPcapField)) {
                        activeField = ActiveField::TrafficPcap;
                    } else if (pointInRect(mouse, trafficReportField)) {
                        activeField = ActiveField::TrafficReport;
                    } else {
                        activeField = ActiveField::None;
                    }

                    if (pointInRect(mouse, browseIfaceButton.bounds)) {
                        openInterfacePicker(&trafficIfaceInput);
                    }
                    if (pointInRect(mouse, browsePcapButton.bounds)) {
                        openPathPicker(&trafficPcapInput, trafficPcapInput, "Select a .pcap file to analyze", false);
                    }
                    if (pointInRect(mouse, browseTrafficReportButton.bounds)) {
                        openPathPicker(&trafficReportInput, trafficReportInput, "Select report output location", true, true);
                    }
                    if (pointInRect(mouse, captureLiveButton.bounds)) {
                        startTrafficCapture(true);
                    }
                    if (pointInRect(mouse, analyzePcapButton.bounds)) {
                        startTrafficCapture(false);
                    }
#endif
                }
            }

            if (event.type == sf::Event::TextEntered) {
                std::string *active = nullptr;
                switch (activeField) {
                case ActiveField::CodeTarget: active = &codeTargetInput; break;
                case ActiveField::CodeReport: active = &codeReportInput; break;
                case ActiveField::NetTarget: active = &netTargetInput; break;
                case ActiveField::NetPortStart: active = &netPortStartInput; break;
                case ActiveField::NetPortEnd: active = &netPortEndInput; break;
                case ActiveField::NetReport: active = &netReportInput; break;
#ifdef EPISCAN_HAVE_PCAP
                case ActiveField::TrafficIface: active = &trafficIfaceInput; break;
                case ActiveField::TrafficPcap: active = &trafficPcapInput; break;
                case ActiveField::TrafficDuration: active = &trafficDurationInput; break;
                case ActiveField::TrafficReport: active = &trafficReportInput; break;
#endif
                default: break;
                }

                if (!active) {
                    continue;
                }

                if (event.text.unicode == 8) {
                    if (!active->empty()) {
                        active->pop_back();
                    }
                } else if (event.text.unicode >= 32 && event.text.unicode < 127) {
                    active->push_back(static_cast<char>(event.text.unicode));
                }
            }
        }

        window.clear(sf::Color(18, 22, 28));

        drawText(window, font, "EpiScan - Security Scanner", 22, 20.f, 70.f, sf::Color(230, 235, 240));
        drawTabBar();

        if (activeTab == Tab::Code) {
            bool scanning = false;
            bool hasResult = false;
            std::size_t processed = 0;
            std::size_t total = 0;
            std::string status;
            std::string current;
            std::filesystem::path reportPath;
            episcan::ScanResult resultSnapshot;

            {
                std::lock_guard<std::mutex> lock(codeShared.mutex);
                scanning = codeShared.scanning;
                hasResult = codeShared.hasResult;
                processed = codeShared.processed;
                total = codeShared.total;
                status = codeShared.status;
                current = codeShared.current.string();
                reportPath = codeShared.reportPath;
                if (hasResult) {
                    resultSnapshot = codeShared.result;
                }
            }

            drawText(window, font, "Target file or directory", 18, 20.f, 112.f, sf::Color(190, 200, 212));
            drawInput(codeTargetField, codeTargetInput, activeField == ActiveField::CodeTarget);
            drawButton(browseTargetButton, sf::Color(70, 95, 130));
            drawText(window, font, "Report file", 18, 20.f, 188.f, sf::Color(190, 200, 212));
            drawInput(codeReportField, codeReportInput, activeField == ActiveField::CodeReport);
            drawButton(browseReportButton, sf::Color(70, 95, 130));

            drawButton(scanTargetButton, scanning ? sf::Color(55, 75, 95) : sf::Color(45, 125, 190));
            drawButton(scanAllButton, scanning ? sf::Color(55, 75, 95) : sf::Color(168, 78, 52));

            drawText(window, font, status, 18, 20.f, 332.f, sf::Color(220, 224, 230));
            if (total > 0) {
                const float progress = static_cast<float>(processed) / static_cast<float>(total);
                sf::RectangleShape barBg(sf::Vector2f(1060.f, 18.f));
                barBg.setPosition(20.f, 366.f);
                barBg.setFillColor(sf::Color(40, 46, 56));
                window.draw(barBg);

                sf::RectangleShape barFg(sf::Vector2f(1060.f * std::min(1.f, progress), 18.f));
                barFg.setPosition(20.f, 366.f);
                barFg.setFillColor(sf::Color(60, 180, 90));
                window.draw(barFg);

                drawText(window, font,
                    std::to_string(processed) + "/" + std::to_string(total) + " - " + truncateMiddle(current, 120),
                    14,
                    20.f,
                    390.f,
                    sf::Color(180, 190, 205));
            }

            if (hasResult) {
                drawText(window, font,
                    "Scanned: " + std::to_string(resultSnapshot.scannedFiles)
                        + " | Detections: " + std::to_string(resultSnapshot.findings.size())
                        + " | Report: " + reportPath.string(),
                    16,
                    20.f,
                    420.f,
                    sf::Color(220, 224, 230));

                drawText(window, font, "Top detections", 18, 20.f, 450.f, sf::Color(200, 210, 224));
                const std::size_t maxLines = std::min<std::size_t>(12, resultSnapshot.findings.size());
                for (std::size_t index = 0; index < maxLines; ++index) {
                    const auto &finding = resultSnapshot.findings[index];
                    const std::string severityStr = episcan::severityToString(finding.severity);
                    const std::string line = severityStr + " | CVSS " + std::to_string(static_cast<int>(finding.cvssScore * 10) / 10.0)
                        + " | " + finding.cwe + " | " + finding.token + " | "
                        + finding.file.string() + ":" + std::to_string(finding.line);
                    drawText(window, font, truncateMiddle(line, 170), 14, 20.f, 478.f + static_cast<float>(index) * 22.f, severityColor(severityStr));
                }
            }
        } else if (activeTab == Tab::Network) {
            bool scanning = false;
            bool hasResult = false;
            std::string status;
            episcan::network::NetworkScanResult resultSnapshot;

            {
                std::lock_guard<std::mutex> lock(netShared.mutex);
                scanning = netShared.scanning;
                hasResult = netShared.hasResult;
                status = netShared.status;
                if (hasResult) {
                    resultSnapshot = netShared.result;
                }
            }

            drawText(window, font, "Target host / IP", 18, 20.f, 112.f, sf::Color(190, 200, 212));
            drawInput(netTargetField, netTargetInput, activeField == ActiveField::NetTarget);
            drawText(window, font, "Port start", 18, 20.f, 188.f, sf::Color(190, 200, 212));
            drawInput(netPortStartField, netPortStartInput, activeField == ActiveField::NetPortStart);
            drawText(window, font, "Port end", 18, 570.f, 188.f, sf::Color(190, 200, 212));
            drawInput(netPortEndField, netPortEndInput, activeField == ActiveField::NetPortEnd);

            drawText(window, font, "Report file", 18, 20.f, 263.f, sf::Color(190, 200, 212));
            drawInput(netReportField, netReportInput, activeField == ActiveField::NetReport);
            drawButton(browseNetReportButton, sf::Color(70, 95, 130));

            drawButton(scanNetworkButton, scanning ? sf::Color(55, 75, 95) : sf::Color(45, 125, 190));

            drawText(window, font, status, 18, 20.f, 408.f, sf::Color(220, 224, 230));

            if (hasResult) {
                drawText(window, font,
                    "Open ports: " + std::to_string(resultSnapshot.services.size())
                        + " | Vulnerabilities: " + std::to_string(resultSnapshot.findings.size())
                        + " | Scanned: " + std::to_string(resultSnapshot.scannedPorts) + " ports",
                    16,
                    20.f,
                    436.f,
                    sf::Color(220, 224, 230));

                drawText(window, font, "Services", 18, 20.f, 466.f, sf::Color(200, 210, 224));
                const std::size_t maxServices = std::min<std::size_t>(8, resultSnapshot.services.size());
                for (std::size_t index = 0; index < maxServices; ++index) {
                    const auto &service = resultSnapshot.services[index];
                    const std::string line = std::to_string(service.port) + " | " + service.service
                        + " | " + service.version + " | " + truncateMiddle(service.banner, 80);
                    drawText(window, font, truncateMiddle(line, 150), 14, 20.f, 494.f + static_cast<float>(index) * 20.f, sf::Color(210, 215, 225));
                }

                const float findingsY = 494.f + static_cast<float>(maxServices) * 20.f + 24.f;
                drawText(window, font, "Findings", 18, 20.f, findingsY, sf::Color(200, 210, 224));
                const std::size_t maxFindings = std::min<std::size_t>(8, resultSnapshot.findings.size());
                for (std::size_t index = 0; index < maxFindings; ++index) {
                    const auto &finding = resultSnapshot.findings[index];
                    const std::string line = episcan::severityToString(finding.severity) + " | " + finding.cwe
                        + " | " + finding.message;
                    drawText(window, font, truncateMiddle(line, 170), 14, 20.f, findingsY + 28.f + static_cast<float>(index) * 20.f,
                        severityColor(episcan::severityToString(finding.severity)));
                }
            }
        } else if (activeTab == Tab::Traffic) {
#ifdef EPISCAN_HAVE_PCAP
            bool running = false;
            bool hasResult = false;
            std::size_t packets = 0;
            std::size_t findingsCount = 0;
            std::string status;
            std::vector<episcan::network::PacketFinding> findingsSnapshot;

            {
                std::lock_guard<std::mutex> lock(trafficShared.mutex);
                running = trafficShared.running;
                hasResult = trafficShared.hasResult;
                packets = trafficShared.packets;
                findingsCount = trafficShared.findingsCount;
                status = trafficShared.status;
                if (hasResult) {
                    findingsSnapshot = trafficShared.findings;
                }
            }

            drawText(window, font, "Interface (live capture)", 18, 20.f, 112.f, sf::Color(190, 200, 212));
            drawInput(trafficIfaceField, trafficIfaceInput, activeField == ActiveField::TrafficIface);
            drawButton(browseIfaceButton, sf::Color(70, 95, 130));
            drawText(window, font, "Duration (s)", 18, 570.f, 112.f, sf::Color(190, 200, 212));
            drawInput(trafficDurationField, trafficDurationInput, activeField == ActiveField::TrafficDuration);

            drawText(window, font, "Pcap file (offline analysis)", 18, 20.f, 188.f, sf::Color(190, 200, 212));
            drawInput(trafficPcapField, trafficPcapInput, activeField == ActiveField::TrafficPcap);
            drawButton(browsePcapButton, sf::Color(70, 95, 130));

            drawText(window, font, "Report file", 18, 20.f, 263.f, sf::Color(190, 200, 212));
            drawInput(trafficReportField, trafficReportInput, activeField == ActiveField::TrafficReport);
            drawButton(browseTrafficReportButton, sf::Color(70, 95, 130));

            drawButton(captureLiveButton, running ? sf::Color(55, 75, 95) : sf::Color(45, 125, 190));
            drawButton(analyzePcapButton, running ? sf::Color(55, 75, 95) : sf::Color(168, 78, 52));

            drawText(window, font, status, 18, 20.f, 408.f, sf::Color(220, 224, 230));
            drawText(window, font,
                "Packets: " + std::to_string(packets) + " | Findings: " + std::to_string(findingsCount),
                16, 20.f, 436.f, sf::Color(220, 224, 230));

            if (hasResult) {
                drawText(window, font, "Top detections", 18, 20.f, 466.f, sf::Color(200, 210, 224));
                const std::size_t maxLines = std::min<std::size_t>(11, findingsSnapshot.size());
                for (std::size_t index = 0; index < maxLines; ++index) {
                    const auto &finding = findingsSnapshot[index];
                    const std::string line = finding.severity + " | " + finding.ruleId + " | "
                        + finding.srcIp + ":" + std::to_string(finding.srcPort) + " -> "
                        + finding.dstIp + ":" + std::to_string(finding.dstPort) + " | " + finding.description;
                    drawText(window, font, truncateMiddle(line, 170), 14, 20.f, 494.f + static_cast<float>(index) * 22.f, severityColor(finding.severity));
                }
            }
#else
            drawText(window, font, "libpcap not available at build time.", 18, 20.f, 112.f, sf::Color(220, 140, 80));
            drawText(window, font, "Install libpcap-dev and rebuild to enable traffic capture.", 16, 20.f, 140.f, sf::Color(190, 200, 212));
#endif
        }

        drawPicker();

        window.display();
    }

    if (codeThread.joinable()) {
        codeThread.join();
    }
    if (netThread.joinable()) {
        netThread.join();
    }
#ifdef EPISCAN_HAVE_PCAP
    if (trafficThread.joinable()) {
        trafficThread.join();
    }
#endif

    return 0;
}
