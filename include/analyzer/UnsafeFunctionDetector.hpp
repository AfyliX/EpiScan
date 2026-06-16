#pragma once
#include "core/Vulnerability.hpp"
#include <filesystem>
#include <vector>

namespace episcan {
namespace analyzer {

// Détecte l'utilisation de fonctions C/C++ dangereuses (gets, strcpy, sprintf…)
std::vector<Vulnerability> detectUnsafeFunctions(const std::filesystem::path &file);

} // namespace analyzer
} // namespace episcan
