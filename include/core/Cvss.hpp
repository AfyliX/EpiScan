#pragma once
#include <string>

namespace episcan {

// CVSS v3.1 base metrics
struct CvssVector {
    // Attack Vector
    enum class AV { Network, Adjacent, Local, Physical } av = AV::Network;
    // Attack Complexity
    enum class AC { Low, High } ac = AC::Low;
    // Privileges Required
    enum class PR { None, Low, High } pr = PR::None;
    // User Interaction
    enum class UI { None, Required } ui = UI::None;
    // Scope
    enum class S { Unchanged, Changed } s = S::Unchanged;
    // Confidentiality / Integrity / Availability Impact
    enum class I { None, Low, High } c = I::High, i = I::High, a = I::High;
};

// Compute CVSS v3.1 base score (0.0–10.0)
double computeCvss31(const CvssVector &vec);

// Parse a CVSS v3.1 vector string: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CvssVector parseCvssVector(const std::string &vectorStr);

// Predefined vectors for common finding categories
CvssVector cvssForCategory(const std::string &category);

} // namespace episcan
