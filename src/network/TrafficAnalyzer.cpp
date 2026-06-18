#include "network/TrafficAnalyzer.hpp"

#include <nlohmann/json.hpp>

#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace episcan {
namespace network {

// ── Detection rule ───────────────────────────────────────────────────────────

struct TrafficRule {
    std::string              id;
    std::vector<std::string> patterns;    // all must appear in payload (case-insensitive)
    std::string              severity;
    std::string              description;
    bool                     tcpOnly  = false;
    bool                     udpOnly  = false;
    uint16_t                 port     = 0;   // 0 = any port; otherwise only on this port
};

// ── Heuristic thresholds ─────────────────────────────────────────────────────

static constexpr uint16_t k_dnsPort        = 53;
static constexpr std::size_t k_dnsTunnelLen = 52;   // subdomain length threshold

// Known ports commonly used by C2 frameworks / RATs
static const std::unordered_set<uint16_t> k_c2Ports = {
    1234, 4444, 4445, 5555, 6666, 6667, 6668,   // classic metasploit / netcat
    8888, 9001, 9090, 9999,                       // Cobalt Strike / misc RATs
    31337                                         // classic "elite" back-door port
};

// ── Rule database ────────────────────────────────────────────────────────────

static std::vector<TrafficRule> buildRules()
{
    return {
        // ── Critical CVEs ─────────────────────────────────────────────────
        {
            "log4shell-ldap",
            {"${jndi:ldap://"},
            "critical",
            "Log4Shell (CVE-2021-44228): JNDI/LDAP injection string in payload"
        },
        {
            "log4shell-rmi",
            {"${jndi:rmi://"},
            "critical",
            "Log4Shell (CVE-2021-44228): JNDI/RMI injection string in payload"
        },
        {
            "log4shell-dns",
            {"${jndi:dns://"},
            "critical",
            "Log4Shell (CVE-2021-44228): JNDI/DNS injection string in payload"
        },
        {
            "shellshock",
            {"() { :;};"},
            "critical",
            "ShellShock (CVE-2014-6271): Bash function-definition injection"
        },
        {
            "log4j-bypass-upper",
            {"${${::-j}${::-n}${::-d}${::-i}:"},
            "critical",
            "Log4Shell obfuscated bypass variant detected"
        },

        // ── Reverse shell payloads ────────────────────────────────────────
        {
            "revshell-bash-i",
            {"bash -i"},
            "high",
            "Reverse shell: bash interactive flag in TCP payload",
            /*tcpOnly=*/true
        },
        {
            "revshell-dev-tcp",
            {"/dev/tcp/"},
            "high",
            "Reverse shell: bash /dev/tcp redirection in payload",
            /*tcpOnly=*/true
        },
        {
            "revshell-nc-e",
            {"nc -e /bin"},
            "high",
            "Reverse shell: netcat -e /bin pattern in payload",
            /*tcpOnly=*/true
        },
        {
            "revshell-python",
            {"import socket", "s.connect(("},
            "high",
            "Python reverse shell one-liner in TCP payload",
            /*tcpOnly=*/true
        },
        {
            "revshell-perl",
            {"use socket;$i="},
            "high",
            "Perl reverse shell one-liner in TCP payload",
            /*tcpOnly=*/true
        },
        {
            "revshell-php",
            {"fsockopen("},
            "high",
            "PHP reverse shell (fsockopen) detected in payload"
        },
        {
            "revshell-ruby",
            {"require 'socket'", "TCPSocket.new("},
            "high",
            "Ruby reverse shell in TCP payload",
            /*tcpOnly=*/true
        },
        {
            "revshell-socat",
            {"socat exec:"},
            "high",
            "Socat reverse shell pattern in payload",
            /*tcpOnly=*/true
        },

        // ── Credential / web-shell patterns ──────────────────────────────
        {
            "php-webshell-eval",
            {"eval(base64_decode("},
            "high",
            "PHP webshell: eval(base64_decode()) pattern"
        },
        {
            "php-webshell-assert",
            {"assert(base64_decode("},
            "high",
            "PHP webshell: assert(base64_decode()) pattern"
        },
        {
            "cleartext-password",
            {"password="},
            "medium",
            "Cleartext credential (password=) transmitted over unencrypted HTTP",
            /*tcpOnly=*/true, /*udpOnly=*/false, /*port=*/80
        },

        // ── Post-exploitation tools ───────────────────────────────────────
        {
            "mimikatz-sekurlsa",
            {"sekurlsa::"},
            "critical",
            "Mimikatz credential dump command (sekurlsa) in traffic"
        },
        {
            "mimikatz-lsadump",
            {"lsadump::"},
            "critical",
            "Mimikatz credential dump command (lsadump) in traffic"
        },
        {
            "mimikatz-kerberos",
            {"kerberos::golden"},
            "critical",
            "Mimikatz Kerberos Golden Ticket command in traffic"
        },
        {
            "cobalt-strike-beacon",
            {"cobaltstrike"},
            "critical",
            "Cobalt Strike string visible in unencrypted traffic"
        },

        // ── SQL injection probes ──────────────────────────────────────────
        {
            "sqli-union-probe",
            {"union select"},
            "medium",
            "SQL injection probe: UNION SELECT in HTTP payload"
        },
        {
            "sqli-drop-probe",
            {"drop table"},
            "medium",
            "SQL injection probe: DROP TABLE in HTTP payload"
        },

        // ── Command injection ─────────────────────────────────────────────
        {
            "cmd-injection-wget-sh",
            {"wget ", "| sh"},
            "high",
            "Command injection: wget pipe to shell"
        },
        {
            "cmd-injection-curl-sh",
            {"curl ", "| sh"},
            "high",
            "Command injection: curl pipe to shell"
        },
    };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

static std::string toLower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static bool containsCI(const std::string &haystack, const std::string &needle)
{
    return toLower(haystack).find(toLower(needle)) != std::string::npos;
}

static std::string makePrintable(const uint8_t *data, std::size_t len, std::size_t maxOut = 80)
{
    std::string out;
    out.reserve(std::min(len, maxOut));
    for (std::size_t i = 0; i < len && out.size() < maxOut; ++i) {
        const char c = static_cast<char>(data[i]);
        out.push_back((c >= 0x20 && c < 0x7f) ? c : '.');
    }
    return out;
}

static std::string ipToString(uint32_t addr)
{
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

// ── Port-scan tracking (stateful) ────────────────────────────────────────────

struct PortScanTracker {
    std::mutex                                                 mtx;
    std::unordered_map<std::string, std::unordered_set<uint16_t>> srcToDstPorts;

    static constexpr std::size_t k_threshold = 20;

    // Returns true (first time) when the source crosses the scan threshold.
    bool record(const std::string &srcIp, uint16_t dstPort)
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto &ports = srcToDstPorts[srcIp];
        const std::size_t before = ports.size();
        ports.insert(dstPort);
        return (before < k_threshold && ports.size() >= k_threshold);
    }
};

// ── DNS tunnelling detection ──────────────────────────────────────────────────

// Very lightweight: look for unusually long labels in the raw DNS query section.
static bool looksLikeDnsTunnel(const uint8_t *payload, std::size_t payloadLen)
{
    if (payloadLen < 13) return false; // minimum DNS header + 1 byte
    // Skip 12-byte DNS header
    const uint8_t *p   = payload + 12;
    const uint8_t *end = payload + payloadLen;
    std::size_t longest = 0;
    while (p < end && *p != 0) {
        const uint8_t labelLen = *p;
        if ((labelLen & 0xC0) == 0xC0) break; // compression pointer
        if (labelLen == 0) break;
        if (labelLen > longest) longest = labelLen;
        p += 1 + labelLen;
    }
    return longest >= k_dnsTunnelLen;
}

// ── Packet parsing & matching ─────────────────────────────────────────────────

struct CaptureContext {
    const std::vector<TrafficRule>  &rules;
    std::vector<PacketFinding>      &findings;
    std::mutex                       findingsMtx;
    std::atomic<std::size_t>         packetCount{0};
    const TrafficCallback           &callback;
    PortScanTracker                  portScan;
    int                              datalinkType = DLT_EN10MB;
};

static void processPacket(CaptureContext               &ctx,
                           const struct pcap_pkthdr     *hdr,
                           const uint8_t                *data)
{
    ++ctx.packetCount;

    // ── Strip link-layer header ──────────────────────────────────────────────
    std::size_t offset = 0;
    if (ctx.datalinkType == DLT_EN10MB) {
        if (hdr->caplen < 14) return;
        const uint16_t ethertype =
            static_cast<uint16_t>((data[12] << 8) | data[13]);
        if (ethertype != 0x0800) return; // only IPv4
        offset = 14;
    } else if (ctx.datalinkType == DLT_NULL || ctx.datalinkType == DLT_LOOP) {
        if (hdr->caplen < 4) return;
        const uint32_t family = *reinterpret_cast<const uint32_t *>(data);
        if (family != AF_INET) return;
        offset = 4;
    } else if (ctx.datalinkType == DLT_RAW) {
        offset = 0;
    } else {
        return; // unsupported link type
    }

    if (hdr->caplen < offset + static_cast<std::size_t>(sizeof(struct ip))) return;

    // ── IPv4 header ──────────────────────────────────────────────────────────
    const struct ip *ipHdr = reinterpret_cast<const struct ip *>(data + offset);
    if (ipHdr->ip_v != 4) return;
    const std::size_t ipHdrLen = static_cast<std::size_t>(ipHdr->ip_hl) * 4;
    if (ipHdrLen < 20) return;

    const std::string srcIp = ipToString(ipHdr->ip_src.s_addr);
    const std::string dstIp = ipToString(ipHdr->ip_dst.s_addr);
    const uint8_t     proto  = ipHdr->ip_p;

    // Ignore fragmented packets (other than the first fragment)
    const uint16_t fragOff =
        ntohs(ipHdr->ip_off) & IP_OFFMASK;
    if (fragOff != 0) return;

    offset += ipHdrLen;

    uint16_t srcPort = 0, dstPort = 0;
    const uint8_t *payload    = nullptr;
    std::size_t    payloadLen = 0;
    std::string    protocol;

    if (proto == IPPROTO_TCP) {
        if (hdr->caplen < offset + static_cast<std::size_t>(sizeof(struct tcphdr))) return;
        const struct tcphdr *tcpHdr =
            reinterpret_cast<const struct tcphdr *>(data + offset);
        srcPort = ntohs(tcpHdr->th_sport);
        dstPort = ntohs(tcpHdr->th_dport);
        const std::size_t tcpHdrLen = static_cast<std::size_t>(tcpHdr->th_off) * 4;
        if (tcpHdrLen < 20) return;

        // Port-scan detection: SYN without ACK
        if ((tcpHdr->th_flags & TH_SYN) && !(tcpHdr->th_flags & TH_ACK)) {
            if (ctx.portScan.record(srcIp, dstPort)) {
                PacketFinding f;
                f.ruleId          = "port-scan";
                f.srcIp           = srcIp;
                f.dstIp           = dstIp;
                f.srcPort         = srcPort;
                f.dstPort         = dstPort;
                f.protocol        = "TCP";
                f.severity        = "medium";
                f.description     = "Port scan detected: " + srcIp
                                    + " sent SYN to " + std::to_string(PortScanTracker::k_threshold)
                                    + "+ distinct ports";
                f.timestamp       = static_cast<std::time_t>(hdr->ts.tv_sec);
                std::lock_guard<std::mutex> lock(ctx.findingsMtx);
                ctx.findings.push_back(std::move(f));
            }
        }

        offset += tcpHdrLen;
        if (hdr->caplen <= offset) return;
        payload    = data + offset;
        payloadLen = hdr->caplen - offset;
        protocol   = "TCP";

        // C2 port check
        if (k_c2Ports.count(dstPort) || k_c2Ports.count(srcPort)) {
            const uint16_t suspicious = k_c2Ports.count(dstPort) ? dstPort : srcPort;
            PacketFinding f;
            f.ruleId       = "c2-known-port";
            f.srcIp        = srcIp;
            f.dstIp        = dstIp;
            f.srcPort      = srcPort;
            f.dstPort      = dstPort;
            f.protocol     = "TCP";
            f.severity     = "medium";
            f.description  = "Traffic on known C2/RAT port " + std::to_string(suspicious);
            f.payloadSnippet = makePrintable(payload, payloadLen);
            f.timestamp    = static_cast<std::time_t>(hdr->ts.tv_sec);
            std::lock_guard<std::mutex> lock(ctx.findingsMtx);
            ctx.findings.push_back(std::move(f));
        }

    } else if (proto == IPPROTO_UDP) {
        if (hdr->caplen < offset + 8u) return;
        const struct udphdr *udpHdr =
            reinterpret_cast<const struct udphdr *>(data + offset);
        srcPort = ntohs(udpHdr->uh_sport);
        dstPort = ntohs(udpHdr->uh_dport);
        offset += 8;
        if (hdr->caplen <= offset) return;
        payload    = data + offset;
        payloadLen = hdr->caplen - offset;
        protocol   = "UDP";

        // DNS tunnelling
        if ((dstPort == k_dnsPort || srcPort == k_dnsPort)
            && looksLikeDnsTunnel(payload, payloadLen))
        {
            PacketFinding f;
            f.ruleId       = "dns-tunneling";
            f.srcIp        = srcIp;
            f.dstIp        = dstIp;
            f.srcPort      = srcPort;
            f.dstPort      = dstPort;
            f.protocol     = "UDP";
            f.severity     = "medium";
            f.description  = "DNS tunnelling heuristic: abnormally long label in query";
            f.payloadSnippet = makePrintable(payload, payloadLen);
            f.timestamp    = static_cast<std::time_t>(hdr->ts.tv_sec);
            std::lock_guard<std::mutex> lock(ctx.findingsMtx);
            ctx.findings.push_back(std::move(f));
        }
    } else {
        return;
    }

    if (payload == nullptr || payloadLen == 0) return;

    // ── Convert payload to string for text-pattern matching ──────────────────
    const std::string payloadStr(reinterpret_cast<const char *>(payload), payloadLen);

    // ── Apply signature rules ─────────────────────────────────────────────────
    for (const auto &rule : ctx.rules) {
        if (rule.patterns.empty()) continue;
        if (rule.tcpOnly && protocol != "TCP") continue;
        if (rule.udpOnly && protocol != "UDP") continue;
        if (rule.port != 0 && rule.port != dstPort && rule.port != srcPort) continue;

        bool allMatch = true;
        for (const auto &pat : rule.patterns) {
            if (!containsCI(payloadStr, pat)) {
                allMatch = false;
                break;
            }
        }
        if (!allMatch) continue;

        PacketFinding f;
        f.ruleId         = rule.id;
        f.srcIp          = srcIp;
        f.dstIp          = dstIp;
        f.srcPort        = srcPort;
        f.dstPort        = dstPort;
        f.protocol       = protocol;
        f.severity       = rule.severity;
        f.description    = rule.description;
        f.payloadSnippet = makePrintable(payload, payloadLen);
        f.timestamp      = static_cast<std::time_t>(hdr->ts.tv_sec);

        std::lock_guard<std::mutex> lock(ctx.findingsMtx);
        ctx.findings.push_back(std::move(f));
    }

    // Progress notification every 100 packets
    if (ctx.callback && (ctx.packetCount.load() % 100 == 0)) {
        std::size_t n;
        {
            std::lock_guard<std::mutex> lock(ctx.findingsMtx);
            n = ctx.findings.size();
        }
        ctx.callback(ctx.packetCount.load(), n);
    }
}

// pcap_handler callback (C linkage)
static void pcapHandler(uint8_t *user,
                         const struct pcap_pkthdr *hdr,
                         const uint8_t            *data)
{
    auto *ctx = reinterpret_cast<CaptureContext *>(user);
    processPacket(*ctx, hdr, data);
}

// ── Public API ────────────────────────────────────────────────────────────────

std::vector<PacketFinding> analyzeTraffic(const TrafficScanOptions &opts,
                                          const TrafficCallback    &cb)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t *handle = nullptr;

    const std::vector<TrafficRule> rules = buildRules();
    std::vector<PacketFinding>     findings;
    CaptureContext ctx{rules, findings, {}, {}, cb, {}, DLT_EN10MB};

    if (!opts.pcapFile.empty()) {
        // ── Offline mode: read from .pcap file ───────────────────────────
        handle = pcap_open_offline(opts.pcapFile.c_str(), errbuf);
        if (!handle) {
            throw std::runtime_error(std::string("pcap_open_offline failed: ") + errbuf);
        }
    } else {
        // ── Live capture mode ─────────────────────────────────────────────
        handle = pcap_open_live(
            opts.interface.c_str(),
            65535,    // snaplen
            1,        // promiscuous
            1000,     // read timeout ms
            errbuf
        );
        if (!handle) {
            throw std::runtime_error(std::string("pcap_open_live failed: ") + errbuf);
        }
    }

    ctx.datalinkType = pcap_datalink(handle);

    // ── Timer thread to stop live capture after durationSeconds ─────────────
    std::thread timer;
    if (opts.pcapFile.empty() && opts.durationSeconds > 0) {
        timer = std::thread([handle, &opts]() {
            std::this_thread::sleep_for(
                std::chrono::seconds(opts.durationSeconds));
            pcap_breakloop(handle);
        });
    }

    // ── Capture loop ─────────────────────────────────────────────────────────
    pcap_loop(handle,
              opts.maxPackets > 0 ? opts.maxPackets : -1,
              pcapHandler,
              reinterpret_cast<uint8_t *>(&ctx));

    pcap_close(handle);

    if (timer.joinable()) {
        timer.join();
    }

    // Final callback
    if (cb) {
        cb(ctx.packetCount.load(), findings.size());
    }

    return findings;
}

// ── JSON report ───────────────────────────────────────────────────────────────

void writeTrafficReport(const std::filesystem::path      &path,
                        const std::vector<PacketFinding> &findings)
{
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("Cannot open report file: " + path.string());
    }

    nlohmann::json j;
    j["findings"] = nlohmann::json::array();
    for (const auto &f : findings) {
        j["findings"].push_back({
            {"ruleId", f.ruleId},
            {"severity", f.severity},
            {"description", f.description},
            {"src", f.srcIp + ":" + std::to_string(f.srcPort)},
            {"dst", f.dstIp + ":" + std::to_string(f.dstPort)},
            {"protocol", f.protocol},
            {"payloadSnippet", f.payloadSnippet},
            {"timestamp", f.timestamp},
        });
    }
    j["totalFindings"] = findings.size();

    out << j.dump(2) << "\n";
}

// ── Interface enumeration ─────────────────────────────────────────────────────

std::vector<std::string> listInterfaces()
{
    std::vector<std::string> result;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t *devs = nullptr;

    if (pcap_findalldevs(&devs, errbuf) != 0 || devs == nullptr) {
        return result;
    }

    for (pcap_if_t *d = devs; d != nullptr; d = d->next) {
        if (d->name) {
            result.emplace_back(d->name);
        }
    }

    pcap_freealldevs(devs);
    return result;
}

} // namespace network
} // namespace episcan
