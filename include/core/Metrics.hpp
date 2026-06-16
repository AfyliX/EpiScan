#pragma once
#include "Vulnerability.hpp"
#include <map>
#include <string>
#include <vector>

namespace episcan {

struct ScanMetrics {
    // Répartition par catégorie
    std::map<std::string, std::size_t> countByCategory;
    // Répartition par sévérité
    std::map<std::string, std::size_t> countBySeverity;
    // Score de sécurité (0–100)
    double securityScore = 100.0;
    // CVSS moyen et max
    double avgCvss = 0.0;
    double maxCvss = 0.0;
    // Temps de scan par module (secondes)
    std::map<std::string, double> durationByModule;
    // Totaux
    std::size_t totalFindings  = 0;
    std::size_t scannedFiles   = 0;
    std::size_t scannedPorts   = 0;
    double      totalDurationSec = 0.0;
};

ScanMetrics computeMetrics(const std::vector<Vulnerability> &findings,
                            std::size_t                      scannedFiles  = 0,
                            std::size_t                      scannedPorts  = 0,
                            double                           durationSec   = 0.0);

void printMetrics(const ScanMetrics &m);

} // namespace episcan
