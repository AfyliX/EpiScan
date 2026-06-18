#pragma once
#include "ServiceDetector.hpp"
#include "core/Vulnerability.hpp"

#include <string>
#include <vector>

namespace episcan {
namespace network {

// ── Live NVD CVE lookup (#73, opt-in via NetworkScanOptions.cveCheck) ───────
//
// Offline by default: EpiScan's normal vulnerable-service check
// (checkServiceVulns in NetworkvulAnalyzer.cpp) is a local signature table
// and needs no network access. This module adds an *optional* live query
// against the NVD REST API (https://services.nvd.nist.gov), only performed
// when explicitly requested, so the tool's default behavior stays
// air-gapped-friendly (see docs/benchmark.md).
//
// Practical limits, by design:
//  - CPE matching is a best-effort regex guess from the banner string, not a
//    real CPE dictionary lookup — it can miss or mismatch unusual banners.
//  - Requests are rate-limited (NVD allows ~5 req/30s without an API key) and
//    cached locally for a few days to avoid re-querying on every scan.
//  - Any network failure (offline target, NVD downtime/rate-limit/WAF
//    challenge) is swallowed silently — this must never make a scan fail.

// Best-effort CPE 2.3 string from a detected service's banner/version.
// Returns an empty string if no known product pattern matches.
std::string guessCpe(const ServiceInfo &service);

// Query NVD for CVEs matching this service's guessed CPE. Returns an empty
// vector if no CPE could be guessed, the cache is fresh with no results, or
// the live request fails for any reason (network, rate limit, parse error).
std::vector<Vulnerability> lookupNvdCves(const ServiceInfo &service, const std::string &host);

} // namespace network
} // namespace episcan
