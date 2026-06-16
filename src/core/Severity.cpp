#include "core/Severity.hpp"

namespace episcan {

std::string severityToString(Severity s)
{
    switch (s) {
    case Severity::Low:      return "low";
    case Severity::Medium:   return "medium";
    case Severity::High:     return "high";
    case Severity::Critical: return "critical";
    }
    return "unknown";
}

Severity severityFromString(const std::string &s)
{
    if (s == "critical") return Severity::Critical;
    if (s == "high")     return Severity::High;
    if (s == "medium")   return Severity::Medium;
    return Severity::Low;
}

double severityToCvss(Severity s)
{
    switch (s) {
    case Severity::Critical: return 9.0;
    case Severity::High:     return 7.5;
    case Severity::Medium:   return 5.0;
    case Severity::Low:      return 2.0;
    }
    return 0.0;
}

} // namespace episcan
