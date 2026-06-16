#pragma once
#include "core/Vulnerability.hpp"
#include <filesystem>
#include <vector>

namespace episcan {
namespace analyzer {

// Détecte algorithmes cryptographiques faibles et secrets hardcodés
std::vector<Vulnerability> detectCryptoIssues(const std::filesystem::path &file);

} // namespace analyzer
} // namespace episcan
