#pragma once
#include "core/Vulnerability.hpp"
#include "core/Config.hpp"
#include <filesystem>
#include <vector>

namespace episcan {
namespace analyzer {

// Lance tous les analyseurs de code sur un fichier et agrège les résultats
std::vector<Vulnerability> parseAndAnalyzeFile(const std::filesystem::path &file,
                                                const ScanConfig            &cfg = {});

// Lance tous les analyseurs sur un répertoire (récursif)
std::vector<Vulnerability> analyzeDirectory(const std::filesystem::path &dir,
                                             const ScanConfig            &cfg = {},
                                             std::size_t                 *scannedFiles = nullptr);

} // namespace analyzer
} // namespace episcan
