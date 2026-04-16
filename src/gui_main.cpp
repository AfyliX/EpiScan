#include "app/ScannerEngine.hpp"

#include <SFML/Graphics.hpp>

#include <algorithm>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

struct Button {
    sf::FloatRect bounds;
    std::string label;
};

struct SharedState {
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
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"
    };

    for (const auto &path : candidates) {
        if (font.loadFromFile(path)) {
            return true;
        }
    }
    return false;
}

} // namespace

int main()
{
    sf::RenderWindow window(sf::VideoMode(1100, 760), "EpiScan - SFML Security Scanner");
    window.setFramerateLimit(60);

    sf::Font font;
    if (!loadUiFont(font)) {
        return 1;
    }

    std::string targetInput = std::filesystem::current_path().string();
    std::string reportInput = (std::filesystem::current_path() / "report_gui.json").string();

    enum class ActiveField {
        None,
        Target,
        Report
    };

    ActiveField activeField = ActiveField::None;

    const sf::FloatRect targetField(20.f, 90.f, 1060.f, 40.f);
    const sf::FloatRect reportField(20.f, 165.f, 1060.f, 40.f);
    const Button scanTargetButton {{20.f, 225.f, 260.f, 44.f}, "Scan Target"};
    const Button scanAllButton {{300.f, 225.f, 260.f, 44.f}, "Scan All System"};

    SharedState shared;
    std::thread scanThread;

    auto startScan = [&](bool allSystem) {
        std::lock_guard<std::mutex> lock(shared.mutex);
        if (shared.scanning) {
            return;
        }

        shared.scanning = true;
        shared.hasResult = false;
        shared.processed = 0;
        shared.total = 0;
        shared.current.clear();
        shared.status = allSystem ? "Scanning all system..." : "Scanning target...";

        const std::filesystem::path targetPath = allSystem ? std::filesystem::path("/") : std::filesystem::path(targetInput);
        const std::filesystem::path reportPath = std::filesystem::path(reportInput);

        if (scanThread.joinable()) {
            scanThread.join();
        }

        scanThread = std::thread([&, targetPath, reportPath, allSystem]() {
            try {
                episcan::ScanOptions options;
                options.codePath = targetPath;
                options.reportPath = reportPath;
                options.scanAllSystem = allSystem;

                auto result = episcan::runScan(options, [&](const episcan::ScanProgress &progress) {
                    std::lock_guard<std::mutex> progressLock(shared.mutex);
                    shared.processed = progress.processedFiles;
                    shared.total = progress.totalFiles;
                    shared.current = progress.currentFile;
                });

                episcan::writeReport(reportPath, targetPath, result);

                std::lock_guard<std::mutex> doneLock(shared.mutex);
                shared.result = std::move(result);
                shared.hasResult = true;
                shared.scanning = false;
                shared.reportPath = reportPath;
                shared.status = "Scan completed";
            } catch (const std::exception &error) {
                std::lock_guard<std::mutex> errorLock(shared.mutex);
                shared.scanning = false;
                shared.hasResult = false;
                shared.status = std::string("Error: ") + error.what();
            }
        });
    };

    while (window.isOpen()) {
        sf::Event event;
        while (window.pollEvent(event)) {
            if (event.type == sf::Event::Closed) {
                window.close();
            }

            if (event.type == sf::Event::MouseButtonPressed && event.mouseButton.button == sf::Mouse::Left) {
                const sf::Vector2f mouse(static_cast<float>(event.mouseButton.x), static_cast<float>(event.mouseButton.y));

                if (pointInRect(mouse, targetField)) {
                    activeField = ActiveField::Target;
                } else if (pointInRect(mouse, reportField)) {
                    activeField = ActiveField::Report;
                } else {
                    activeField = ActiveField::None;
                }

                if (pointInRect(mouse, scanTargetButton.bounds)) {
                    startScan(false);
                }
                if (pointInRect(mouse, scanAllButton.bounds)) {
                    startScan(true);
                }
            }

            if (event.type == sf::Event::TextEntered) {
                std::string *active = nullptr;
                if (activeField == ActiveField::Target) {
                    active = &targetInput;
                } else if (activeField == ActiveField::Report) {
                    active = &reportInput;
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

        bool scanning = false;
        bool hasResult = false;
        std::size_t processed = 0;
        std::size_t total = 0;
        std::string status;
        std::string current;
        std::filesystem::path reportPath;
        episcan::ScanResult resultSnapshot;

        {
            std::lock_guard<std::mutex> lock(shared.mutex);
            scanning = shared.scanning;
            hasResult = shared.hasResult;
            processed = shared.processed;
            total = shared.total;
            status = shared.status;
            current = shared.current.string();
            reportPath = shared.reportPath;
            if (hasResult) {
                resultSnapshot = shared.result;
            }
        }

        window.clear(sf::Color(18, 22, 28));

        drawText(window, font, "EpiScan - Security Scanner", 30, 20.f, 18.f, sf::Color(230, 235, 240));
        drawText(window, font, "Target directory", 18, 20.f, 64.f, sf::Color(190, 200, 212));

        auto drawInput = [&](const sf::FloatRect &rect, const std::string &value, bool selected) {
            sf::RectangleShape box(sf::Vector2f(rect.width, rect.height));
            box.setPosition(rect.left, rect.top);
            box.setFillColor(sf::Color(28, 34, 43));
            box.setOutlineThickness(2.f);
            box.setOutlineColor(selected ? sf::Color(86, 166, 255) : sf::Color(70, 78, 90));
            window.draw(box);
            drawText(window, font, truncateMiddle(value, 150), 17, rect.left + 10.f, rect.top + 8.f, sf::Color(235, 240, 245));
        };

        drawInput(targetField, targetInput, activeField == ActiveField::Target);
        drawText(window, font, "Report file", 18, 20.f, 140.f, sf::Color(190, 200, 212));
        drawInput(reportField, reportInput, activeField == ActiveField::Report);

        auto drawButton = [&](const Button &button, const sf::Color &color) {
            sf::RectangleShape shape(sf::Vector2f(button.bounds.width, button.bounds.height));
            shape.setPosition(button.bounds.left, button.bounds.top);
            shape.setFillColor(color);
            shape.setOutlineThickness(1.f);
            shape.setOutlineColor(sf::Color(90, 95, 110));
            window.draw(shape);
            drawText(window, font, button.label, 18, button.bounds.left + 20.f, button.bounds.top + 10.f, sf::Color::White);
        };

        drawButton(scanTargetButton, scanning ? sf::Color(55, 75, 95) : sf::Color(45, 125, 190));
        drawButton(scanAllButton, scanning ? sf::Color(55, 75, 95) : sf::Color(168, 78, 52));

        drawText(window, font, status, 18, 20.f, 285.f, sf::Color(220, 224, 230));
        if (total > 0) {
            const float progress = static_cast<float>(processed) / static_cast<float>(total);
            sf::RectangleShape barBg(sf::Vector2f(1060.f, 18.f));
            barBg.setPosition(20.f, 318.f);
            barBg.setFillColor(sf::Color(40, 46, 56));
            window.draw(barBg);

            sf::RectangleShape barFg(sf::Vector2f(1060.f * std::min(1.f, progress), 18.f));
            barFg.setPosition(20.f, 318.f);
            barFg.setFillColor(sf::Color(60, 180, 90));
            window.draw(barFg);

            drawText(window, font,
                std::to_string(processed) + "/" + std::to_string(total) + " - " + truncateMiddle(current, 120),
                14,
                20.f,
                342.f,
                sf::Color(180, 190, 205));
        }

        if (hasResult) {
            drawText(window, font,
                "Scanned: " + std::to_string(resultSnapshot.scannedFiles)
                    + " | Detections: " + std::to_string(resultSnapshot.findings.size())
                    + " | Report: " + reportPath.string(),
                16,
                20.f,
                372.f,
                sf::Color(220, 224, 230));

            drawText(window, font, "Top detections", 18, 20.f, 402.f, sf::Color(200, 210, 224));
            const std::size_t maxLines = std::min<std::size_t>(12, resultSnapshot.findings.size());
            for (std::size_t index = 0; index < maxLines; ++index) {
                const auto &finding = resultSnapshot.findings[index];
                const std::string line = finding.severity + " | " + finding.matchedToken + " | "
                    + finding.file.string() + ":" + std::to_string(finding.line);
                drawText(window, font, truncateMiddle(line, 170), 14, 20.f, 430.f + static_cast<float>(index) * 22.f, sf::Color(210, 215, 225));
            }
        }

        window.display();
    }

    if (scanThread.joinable()) {
        scanThread.join();
    }

    return 0;
}
