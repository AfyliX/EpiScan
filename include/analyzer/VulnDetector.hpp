#pragma once
#include "core/Vulnerability.hpp"
#include <filesystem>
#include <vector>

namespace episcan {
namespace analyzer {

// Détecte buffer overflow, use-after-free, double-free, variables non initialisées
std::vector<Vulnerability> detectBufferVulns(const std::filesystem::path &file);

} // namespace analyzer
} // namespace episcan
