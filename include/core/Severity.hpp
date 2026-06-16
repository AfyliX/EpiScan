#pragma once
#include <string>

namespace episcan {

enum class Severity { Low, Medium, High, Critical };

std::string severityToString(Severity s);
Severity    severityFromString(const std::string &s);
double      severityToCvss(Severity s);

} // namespace episcan
