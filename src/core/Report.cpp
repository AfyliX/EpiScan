#include "core/Report.hpp"
#include "core/Severity.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace episcan {
namespace {

std::string nowIso8601()
{
    const auto now   = std::chrono::system_clock::now();
    const auto nowT  = std::chrono::system_clock::to_time_t(now);
    std::tm    utc   = {};
#if defined(_WIN32)
    gmtime_s(&utc, &nowT);
#else
    gmtime_r(&nowT, &utc);
#endif
    std::ostringstream ss;
    ss << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string htmlEsc(const std::string &s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&':  out += "&amp;";  break;
        case '<':  out += "&lt;";   break;
        case '>':  out += "&gt;";   break;
        case '"':  out += "&quot;"; break;
        case '\'': out += "&#39;";  break;
        default:   out.push_back(c); break;
        }
    }
    return out;
}

double computeSecurityScore(const std::vector<Vulnerability> &findings)
{
    double score = 100.0;
    for (const auto &v : findings) {
        switch (v.severity) {
        case Severity::Critical: score -= 15.0; break;
        case Severity::High:     score -= 8.0;  break;
        case Severity::Medium:   score -= 3.0;  break;
        case Severity::Low:      score -= 1.0;  break;
        }
    }
    return std::max(0.0, score);
}

std::string severityBadge(Severity s)
{
    switch (s) {
    case Severity::Critical: return "🔴 Critical";
    case Severity::High:     return "🟠 High";
    case Severity::Medium:   return "🟡 Medium";
    case Severity::Low:      return "🟢 Low";
    }
    return "Unknown";
}

std::string severityHtmlColor(Severity s)
{
    switch (s) {
    case Severity::Critical: return "#c0392b";
    case Severity::High:     return "#e67e22";
    case Severity::Medium:   return "#f1c40f";
    case Severity::Low:      return "#27ae60";
    }
    return "#888";
}

} // namespace

Report buildReport(const std::string              &target,
                   const std::vector<Vulnerability> &findings,
                   std::size_t                      scannedFiles,
                   std::size_t                      scannedPorts,
                   double                           durationSec)
{
    Report r;
    r.scanDate = nowIso8601();
    r.target   = target;
    r.findings = findings;

    for (const auto &v : findings) {
        ++r.summary.total;
        switch (v.severity) {
        case Severity::Critical: ++r.summary.critical; break;
        case Severity::High:     ++r.summary.high;     break;
        case Severity::Medium:   ++r.summary.medium;   break;
        case Severity::Low:      ++r.summary.low;      break;
        }
    }
    r.summary.securityScore  = computeSecurityScore(findings);
    r.summary.scannedFiles   = scannedFiles;
    r.summary.scannedPorts   = scannedPorts;
    r.summary.scanDurationSec = durationSec;
    return r;
}

// ── JSON (#80) ────────────────────────────────────────────────────────────────

void writeReportJson(const std::filesystem::path &path, const Report &report)
{
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Cannot open report: " + path.string());

    nlohmann::json j;
    j["scan_date"] = report.scanDate;
    j["target"]    = report.target;
    j["summary"]   = {
        {"critical", report.summary.critical},
        {"high", report.summary.high},
        {"medium", report.summary.medium},
        {"low", report.summary.low},
        {"total", report.summary.total},
        {"security_score", report.summary.securityScore},
        {"scanned_files", report.summary.scannedFiles},
        {"scanned_ports", report.summary.scannedPorts},
        {"scan_duration_sec", report.summary.scanDurationSec},
    };

    j["findings"] = nlohmann::json::array();
    for (const auto &v : report.findings) {
        j["findings"].push_back({
            {"id", v.id},
            {"file", v.file.string()},
            {"line", v.line},
            {"severity", severityToString(v.severity)},
            {"cvss", v.cvssScore},
            {"category", v.category},
            {"message", v.message},
            {"cwe", v.cwe},
            {"remediation", v.remediation},
            {"code", v.code},
        });
    }

    out << j.dump(2) << "\n";
}

// ── HTML (#81) ────────────────────────────────────────────────────────────────

void writeReportHtml(const std::filesystem::path &path, const Report &report)
{
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Cannot open report: " + path.string());

    out << R"(<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EpiScan Security Report</title>
<style>
  body{font-family:system-ui,sans-serif;background:#0f1117;color:#e0e6f0;margin:0;padding:24px}
  h1{color:#56a6ff;margin-bottom:4px}
  .meta{color:#8899aa;font-size:.9em;margin-bottom:24px}
  .dashboard{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px}
  .card{background:#1a1f2e;border-radius:8px;padding:18px 24px;min-width:120px;text-align:center}
  .card .num{font-size:2em;font-weight:700}
  .card .label{font-size:.8em;color:#8899aa;margin-top:4px}
  .critical{color:#c0392b} .high{color:#e67e22} .medium{color:#f1c40f} .low{color:#27ae60}
  .score{color:#56a6ff}
  table{width:100%;border-collapse:collapse;margin-top:8px}
  th{background:#1a1f2e;text-align:left;padding:10px 12px;font-size:.85em;color:#8899aa}
  td{padding:10px 12px;border-bottom:1px solid #1e2535;font-size:.88em;vertical-align:top}
  tr:hover td{background:#1a1f2e}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.78em;font-weight:600;color:#fff}
  .code{font-family:monospace;font-size:.82em;background:#11151f;padding:4px 8px;border-radius:4px;color:#aad8ff}
  .rem{color:#7fba8a;font-size:.83em}
  a{color:#56a6ff}
</style>
</head>
<body>
)";

    out << "<h1>EpiScan — Security Report</h1>\n"
        << "<div class=\"meta\">Cible : <b>" << htmlEsc(report.target) << "</b> &nbsp;|&nbsp; "
        << "Scan : " << htmlEsc(report.scanDate) << " &nbsp;|&nbsp; "
        << "Fichiers : " << report.summary.scannedFiles << " &nbsp;|&nbsp; "
        << "Ports : " << report.summary.scannedPorts << "</div>\n"
        << "<div class=\"dashboard\">\n"
        << "  <div class=\"card\"><div class=\"num critical\">" << report.summary.critical << "</div><div class=\"label\">Critical</div></div>\n"
        << "  <div class=\"card\"><div class=\"num high\">"     << report.summary.high     << "</div><div class=\"label\">High</div></div>\n"
        << "  <div class=\"card\"><div class=\"num medium\">"   << report.summary.medium   << "</div><div class=\"label\">Medium</div></div>\n"
        << "  <div class=\"card\"><div class=\"num low\">"      << report.summary.low      << "</div><div class=\"label\">Low</div></div>\n"
        << "  <div class=\"card\"><div class=\"num score\">"
        << std::fixed << std::setprecision(0) << report.summary.securityScore
        << "/100</div><div class=\"label\">Score de sécurité</div></div>\n"
        << "</div>\n"
        << "<table>\n"
        << "<tr><th>Sévérité</th><th>Fichier / Port</th><th>Ligne</th><th>Catégorie</th>"
        << "<th>Message</th><th>CVSS</th><th>Code</th><th>Remédiation</th></tr>\n";

    for (const auto &v : report.findings) {
        const std::string col = severityHtmlColor(v.severity);
        out << "<tr>\n"
            << "  <td><span class=\"badge\" style=\"background:" << col << "\">"
            << htmlEsc(severityToString(v.severity)) << "</span></td>\n"
            << "  <td>" << htmlEsc(v.file.string()) << "</td>\n"
            << "  <td>" << v.line << "</td>\n"
            << "  <td>" << htmlEsc(v.category) << "</td>\n"
            << "  <td>" << htmlEsc(v.message) << "</td>\n"
            << "  <td>" << std::setprecision(1) << v.cvssScore << "</td>\n"
            << "  <td><span class=\"code\">" << htmlEsc(v.code) << "</span></td>\n"
            << "  <td class=\"rem\">" << htmlEsc(v.remediation) << "</td>\n"
            << "</tr>\n";
    }

    out << "</table>\n</body>\n</html>\n";
}

// ── Markdown (#82) ────────────────────────────────────────────────────────────

void writeReportMarkdown(const std::filesystem::path &path, const Report &report)
{
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Cannot open report: " + path.string());

    out << "# EpiScan — Rapport de Sécurité\n\n"
        << "**Cible :** " << report.target << "  \n"
        << "**Date :** "  << report.scanDate << "  \n"
        << "**Fichiers scannés :** " << report.summary.scannedFiles << "  \n"
        << "**Ports scannés :** "    << report.summary.scannedPorts << "\n\n"
        << "## Résumé\n\n"
        << "| Sévérité | Nombre |\n"
        << "|----------|--------|\n"
        << "| 🔴 Critical | " << report.summary.critical << " |\n"
        << "| 🟠 High     | " << report.summary.high     << " |\n"
        << "| 🟡 Medium   | " << report.summary.medium   << " |\n"
        << "| 🟢 Low      | " << report.summary.low      << " |\n"
        << "| **Total**   | **" << report.summary.total  << "** |\n\n"
        << "**Score de sécurité global :** "
        << std::fixed << std::setprecision(0) << report.summary.securityScore << " / 100\n\n"
        << "## Findings\n\n"
        << "| # | Sévérité | Fichier | Ligne | Catégorie | Message | CVSS |\n"
        << "|---|----------|---------|-------|-----------|---------|------|\n";

    for (std::size_t i = 0; i < report.findings.size(); ++i) {
        const auto &v = report.findings[i];
        out << "| " << (i + 1)
            << " | " << severityBadge(v.severity)
            << " | `" << v.file.string() << "`"
            << " | " << v.line
            << " | " << v.category
            << " | " << v.message
            << " | " << std::setprecision(1) << v.cvssScore
            << " |\n";
    }

    if (!report.findings.empty()) {
        out << "\n## Détails et Remédiation\n\n";
        for (std::size_t i = 0; i < report.findings.size(); ++i) {
            const auto &v = report.findings[i];
            out << "### " << (i + 1) << ". " << v.message << "\n\n"
                << "- **Sévérité :** " << severityBadge(v.severity) << "\n"
                << "- **Fichier :** `" << v.file.string() << ":" << v.line << "`\n"
                << "- **CVSS :** " << std::setprecision(1) << v.cvssScore << "\n"
                << "- **CWE :** " << (v.cwe.empty() ? "N/A" : v.cwe) << "\n"
                << "- **Code :** `" << v.code << "`\n"
                << "- **Remédiation :** " << (v.remediation.empty() ? "Voir doc OWASP." : v.remediation) << "\n\n";
        }
    }

    out << "---\n*Généré par EpiScan*\n";
}

// ── Format auto-selection + scan-to-scan delta ──────────────────────────────

void writeReportAuto(const std::filesystem::path &path, const Report &report)
{
    auto ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return std::tolower(c); });

    if (ext == ".html" || ext == ".htm") {
        writeReportHtml(path, report);
    } else if (ext == ".md" || ext == ".markdown") {
        writeReportMarkdown(path, report);
    } else {
        writeReportJson(path, report);
    }
}

void applyPreviousScanDelta(Report &report, const std::filesystem::path &previousReportPath)
{
    std::ifstream in(previousReportPath);
    if (!in) {
        return;
    }

    try {
        const nlohmann::json previous = nlohmann::json::parse(in);
        const long previousTotal = previous.at("summary").at("total").get<long>();
        report.summary.hasPreviousScan = true;
        report.summary.totalDelta = static_cast<long>(report.summary.total) - previousTotal;
    } catch (const nlohmann::json::exception &) {
        // Previous report missing, unreadable, or not our JSON schema (e.g. HTML/MD) — no delta.
    }
}

} // namespace episcan
