#include "core/Metrics.hpp"
#include "core/Severity.hpp"

#include <algorithm>
#include <iostream>
#include <iomanip>

namespace episcan {

ScanMetrics computeMetrics(const std::vector<Vulnerability> &findings,
                            std::size_t                      scannedFiles,
                            std::size_t                      scannedPorts,
                            double                           durationSec)
{
    ScanMetrics m;
    m.scannedFiles    = scannedFiles;
    m.scannedPorts    = scannedPorts;
    m.totalDurationSec = durationSec;
    m.totalFindings   = findings.size();

    double score = 100.0;
    double sumCvss = 0.0;

    for (const auto &v : findings) {
        m.countByCategory[v.category]++;
        m.countBySeverity[severityToString(v.severity)]++;

        sumCvss += v.cvssScore;
        if (v.cvssScore > m.maxCvss) m.maxCvss = v.cvssScore;

        switch (v.severity) {
        case Severity::Critical: score -= 15.0; break;
        case Severity::High:     score -= 8.0;  break;
        case Severity::Medium:   score -= 3.0;  break;
        case Severity::Low:      score -= 1.0;  break;
        }
    }

    m.securityScore = std::max(0.0, score);
    m.avgCvss = findings.empty() ? 0.0 : sumCvss / static_cast<double>(findings.size());

    return m;
}

void printMetrics(const ScanMetrics &m)
{
    std::cout << "\n══════════════════ EpiScan Metrics ══════════════════\n";
    std::cout << std::fixed << std::setprecision(1);
    std::cout << "  Fichiers scannés   : " << m.scannedFiles << "\n";
    std::cout << "  Ports scannés      : " << m.scannedPorts << "\n";
    std::cout << "  Durée totale       : " << m.totalDurationSec << "s\n";
    std::cout << "  Findings totaux    : " << m.totalFindings << "\n";
    std::cout << "  Score de sécurité  : " << m.securityScore << " / 100\n";
    std::cout << "  CVSS moyen         : " << m.avgCvss << "\n";
    std::cout << "  CVSS max           : " << m.maxCvss << "\n";

    if (!m.countBySeverity.empty()) {
        std::cout << "\n  Répartition par sévérité:\n";
        for (const auto &[sev, cnt] : m.countBySeverity) {
            std::cout << "    " << std::setw(10) << std::left << sev << " : " << cnt << "\n";
        }
    }

    if (!m.countByCategory.empty()) {
        std::cout << "\n  Répartition par catégorie:\n";
        for (const auto &[cat, cnt] : m.countByCategory) {
            std::cout << "    " << std::setw(14) << std::left << cat << " : " << cnt << "\n";
        }
    }
    std::cout << "══════════════════════════════════════════════════════\n";
}

} // namespace episcan
