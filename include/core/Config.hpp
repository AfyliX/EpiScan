#pragma once
#include <cstddef>
#include <string>

namespace episcan {

struct ScanConfig {
    double      minCvssThreshold = 0.0;
    std::size_t maxFindings      = 0;    // 0 = unlimited
    bool        enableNetwork    = true;
    bool        enableCode       = true;
    bool        enableCrypto     = true;
    bool        enableInjection  = true;
    bool        enableBuffer     = true;
    bool        verbose          = false;
};

} // namespace episcan
