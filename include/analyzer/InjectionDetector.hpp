#pragma once
#include "core/Vulnerability.hpp"
#include <filesystem>
#include <vector>

namespace episcan {
namespace analyzer {

// Détecte les patterns d'injection SQL, command injection et path traversal
std::vector<Vulnerability> detectInjections(const std::filesystem::path &file);

} // namespace analyzer
} // namespace episcan
