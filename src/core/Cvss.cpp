#include "core/Cvss.hpp"
#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace episcan {
namespace {

// CVSS v3.1 metric weights per spec (FIRST CVSS v3.1 Document)
double avScore(CvssVector::AV av)
{
    switch (av) {
    case CvssVector::AV::Network:  return 0.85;
    case CvssVector::AV::Adjacent: return 0.62;
    case CvssVector::AV::Local:    return 0.55;
    case CvssVector::AV::Physical: return 0.20;
    }
    return 0.0;
}

double acScore(CvssVector::AC ac)
{
    return ac == CvssVector::AC::Low ? 0.77 : 0.44;
}

double prScore(CvssVector::PR pr, CvssVector::S scope)
{
    const bool changed = (scope == CvssVector::S::Changed);
    switch (pr) {
    case CvssVector::PR::None: return 0.85;
    case CvssVector::PR::Low:  return changed ? 0.68 : 0.62;
    case CvssVector::PR::High: return changed ? 0.50 : 0.27;
    }
    return 0.0;
}

double uiScore(CvssVector::UI ui)
{
    return ui == CvssVector::UI::None ? 0.85 : 0.62;
}

double impactScore(CvssVector::I i)
{
    switch (i) {
    case CvssVector::I::None: return 0.00;
    case CvssVector::I::Low:  return 0.22;
    case CvssVector::I::High: return 0.56;
    }
    return 0.0;
}

// Roundup: round to 1 decimal, away from zero
double roundup(double x)
{
    const long long i = static_cast<long long>(x * 100000.0 + 0.5);
    if (i % 10000 == 0) return static_cast<double>(i) / 100000.0;
    return std::ceil(static_cast<double>(i) / 10000.0) / 10.0;
}

} // namespace

double computeCvss31(const CvssVector &v)
{
    // ISCBase
    const double iscBase = 1.0 - (1.0 - impactScore(v.c))
                                * (1.0 - impactScore(v.i))
                                * (1.0 - impactScore(v.a));

    double iss = 0.0;
    if (v.s == CvssVector::S::Unchanged) {
        iss = 6.42 * iscBase;
    } else {
        iss = 7.52 * (iscBase - 0.029) - 3.25 * std::pow(iscBase - 0.02, 15.0);
    }

    if (iss <= 0.0) return 0.0;

    const double exploitability = 8.22
        * avScore(v.av)
        * acScore(v.ac)
        * prScore(v.pr, v.s)
        * uiScore(v.ui);

    double base = 0.0;
    if (v.s == CvssVector::S::Unchanged) {
        base = std::min(iss + exploitability, 10.0);
    } else {
        base = std::min(1.08 * (iss + exploitability), 10.0);
    }

    return roundup(base);
}

CvssVector parseCvssVector(const std::string &str)
{
    CvssVector v;
    // Look for "/KEY:" or start-of-string to avoid matching "AC:" when looking for "C:"
    auto get = [&](const std::string &key) -> std::string {
        // Try with leading slash first (most components after the first)
        auto pos = str.find("/" + key + ":");
        if (pos != std::string::npos) {
            pos += 1; // skip the slash
        } else {
            // Try at the very beginning
            if (str.size() > key.size() + 1 &&
                str.substr(0, key.size() + 1) == key + ":") {
                pos = 0;
            } else {
                return "";
            }
        }
        const auto start = pos + key.size() + 1;
        const auto end   = str.find('/', start);
        return str.substr(start, end == std::string::npos ? std::string::npos : end - start);
    };

    const auto av = get("AV");
    if      (av == "N") v.av = CvssVector::AV::Network;
    else if (av == "A") v.av = CvssVector::AV::Adjacent;
    else if (av == "L") v.av = CvssVector::AV::Local;
    else if (av == "P") v.av = CvssVector::AV::Physical;

    const auto ac = get("AC");
    v.ac = (ac == "L") ? CvssVector::AC::Low : CvssVector::AC::High;

    const auto pr = get("PR");
    if      (pr == "N") v.pr = CvssVector::PR::None;
    else if (pr == "L") v.pr = CvssVector::PR::Low;
    else if (pr == "H") v.pr = CvssVector::PR::High;

    const auto ui = get("UI");
    v.ui = (ui == "N") ? CvssVector::UI::None : CvssVector::UI::Required;

    const auto s = get("S");
    v.s = (s == "C") ? CvssVector::S::Changed : CvssVector::S::Unchanged;

    auto parseImpact = [](const std::string &val) -> CvssVector::I {
        if (val == "H") return CvssVector::I::High;
        if (val == "L") return CvssVector::I::Low;
        return CvssVector::I::None;
    };

    v.c = parseImpact(get("C"));
    v.i = parseImpact(get("I"));
    v.a = parseImpact(get("A"));

    return v;
}

CvssVector cvssForCategory(const std::string &category)
{
    CvssVector v;
    if (category == "injection") {
        // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8
        v.av = CvssVector::AV::Network;
        v.ac = CvssVector::AC::Low;
        v.pr = CvssVector::PR::None;
        v.ui = CvssVector::UI::None;
        v.s  = CvssVector::S::Unchanged;
        v.c  = CvssVector::I::High;
        v.i  = CvssVector::I::High;
        v.a  = CvssVector::I::High;
    } else if (category == "crypto") {
        // AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N → 5.9
        v.av = CvssVector::AV::Network;
        v.ac = CvssVector::AC::High;
        v.pr = CvssVector::PR::None;
        v.ui = CvssVector::UI::None;
        v.s  = CvssVector::S::Unchanged;
        v.c  = CvssVector::I::High;
        v.i  = CvssVector::I::None;
        v.a  = CvssVector::I::None;
    } else if (category == "buffer") {
        // AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 8.4
        v.av = CvssVector::AV::Local;
        v.ac = CvssVector::AC::Low;
        v.pr = CvssVector::PR::None;
        v.ui = CvssVector::UI::None;
        v.s  = CvssVector::S::Unchanged;
        v.c  = CvssVector::I::High;
        v.i  = CvssVector::I::High;
        v.a  = CvssVector::I::High;
    } else if (category == "unsafe_func") {
        // AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H → 7.8
        v.av = CvssVector::AV::Local;
        v.ac = CvssVector::AC::Low;
        v.pr = CvssVector::PR::None;
        v.ui = CvssVector::UI::Required;
        v.s  = CvssVector::S::Unchanged;
        v.c  = CvssVector::I::High;
        v.i  = CvssVector::I::High;
        v.a  = CvssVector::I::High;
    } else if (category == "ssl") {
        // AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N → 5.9
        v.av = CvssVector::AV::Network;
        v.ac = CvssVector::AC::High;
        v.pr = CvssVector::PR::None;
        v.ui = CvssVector::UI::None;
        v.s  = CvssVector::S::Unchanged;
        v.c  = CvssVector::I::High;
        v.i  = CvssVector::I::None;
        v.a  = CvssVector::I::None;
    } else {
        // Default: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3
        v.av = CvssVector::AV::Network;
        v.ac = CvssVector::AC::Low;
        v.pr = CvssVector::PR::None;
        v.ui = CvssVector::UI::None;
        v.s  = CvssVector::S::Unchanged;
        v.c  = CvssVector::I::Low;
        v.i  = CvssVector::I::None;
        v.a  = CvssVector::I::None;
    }
    return v;
}

} // namespace episcan
