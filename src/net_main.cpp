#include "network/TrafficAnalyzer.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

struct NetOptions {
    std::string            interface   = "any";
    std::string            pcapFile;
    int                    duration    = 30;
    int                    maxPackets  = 0;
    std::filesystem::path  report      = "traffic_report.json";
    bool                   listIfaces  = false;
    bool                   showHelp    = false;
};

void printUsage(const char *prog)
{
    std::cout
        << "Usage: " << prog << " [options]\n"
        << "\n"
        << "Live capture:\n"
        << "  --iface <name>      Network interface to capture on (default: any)\n"
        << "  --duration <secs>   Capture duration in seconds (default: 30)\n"
        << "\n"
        << "Offline analysis:\n"
        << "  --pcap <file.pcap>  Read from a .pcap file instead of live capture\n"
        << "\n"
        << "Common:\n"
        << "  --report <path>     Output report path (default: traffic_report.json)\n"
        << "  --max <n>           Stop after n packets (0 = unlimited)\n"
        << "  --list-ifaces       List available network interfaces and exit\n"
        << "  --help              Show this help message\n"
        << "\n"
        << "Note: live capture requires root or CAP_NET_RAW capability.\n"
        << "      sudo episcan-net --iface eth0 --duration 60\n";
}

NetOptions parseArgs(int argc, char **argv)
{
    NetOptions opts;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            opts.showHelp = true;
            return opts;
        }
        if (arg == "--list-ifaces") {
            opts.listIfaces = true;
            return opts;
        }
        if (arg == "--iface") {
            if (i + 1 >= argc) throw std::runtime_error("Missing value for --iface");
            opts.interface = argv[++i];
        } else if (arg == "--pcap") {
            if (i + 1 >= argc) throw std::runtime_error("Missing value for --pcap");
            opts.pcapFile = argv[++i];
        } else if (arg == "--duration") {
            if (i + 1 >= argc) throw std::runtime_error("Missing value for --duration");
            opts.duration = std::stoi(argv[++i]);
        } else if (arg == "--max") {
            if (i + 1 >= argc) throw std::runtime_error("Missing value for --max");
            opts.maxPackets = std::stoi(argv[++i]);
        } else if (arg == "--report") {
            if (i + 1 >= argc) throw std::runtime_error("Missing value for --report");
            opts.report = argv[++i];
        } else {
            throw std::runtime_error("Unknown argument: " + arg);
        }
    }
    return opts;
}

} // namespace

int main(int argc, char **argv)
{
    NetOptions opts;
    try {
        opts = parseArgs(argc, argv);
    } catch (const std::exception &e) {
        std::cerr << "[episcan-net] error: " << e.what() << "\n";
        printUsage(argv[0]);
        return 1;
    }

    if (opts.showHelp) {
        printUsage(argv[0]);
        return 0;
    }

    if (opts.listIfaces) {
        const auto ifaces = episcan::network::listInterfaces();
        if (ifaces.empty()) {
            std::cout << "(no interfaces found — may require elevated privileges)\n";
        } else {
            for (const auto &name : ifaces) {
                std::cout << "  " << name << "\n";
            }
        }
        return 0;
    }

    episcan::network::TrafficScanOptions scanOpts;
    scanOpts.interface       = opts.interface;
    scanOpts.pcapFile        = opts.pcapFile;
    scanOpts.durationSeconds = opts.duration;
    scanOpts.maxPackets      = opts.maxPackets;
    scanOpts.reportPath      = opts.report;

    const bool isLive = opts.pcapFile.empty();
    if (isLive) {
        std::cout << "[episcan-net] capturing on interface '" << opts.interface
                  << "' for " << opts.duration << "s ...\n";
    } else {
        std::cout << "[episcan-net] analysing pcap file: " << opts.pcapFile << "\n";
    }

    const auto onProgress = [](std::size_t packets, std::size_t findings) {
        std::cout << "\r[scan] packets: " << packets
                  << "  findings: " << findings << std::flush;
    };

    std::vector<episcan::network::PacketFinding> findings;
    try {
        findings = episcan::network::analyzeTraffic(scanOpts, onProgress);
    } catch (const std::exception &e) {
        std::cerr << "\n[episcan-net] error: " << e.what() << "\n";
        return 2;
    }

    std::cout << "\n\n[episcan-net] scan complete.\n"
              << "  Findings : " << findings.size() << "\n";

    // Print summary to stdout
    for (const auto &f : findings) {
        std::cout << "  [" << f.severity << "] " << f.ruleId
                  << " | " << f.srcIp << ":" << f.srcPort
                  << " -> " << f.dstIp << ":" << f.dstPort
                  << "\n    " << f.description << "\n";
    }

    if (!opts.report.empty()) {
        try {
            episcan::network::writeTrafficReport(opts.report, findings);
            std::cout << "  Report   : " << opts.report << "\n";
        } catch (const std::exception &e) {
            std::cerr << "[episcan-net] warning: could not write report: " << e.what() << "\n";
        }
    }

    return 0;
}
