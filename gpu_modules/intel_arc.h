#ifndef INTEL_ARC_H
#define INTEL_ARC_H

#include <vector>

bool is_intel_arc_available();
void shutdown_intel_arc();
bool gpu_generate_scoops(const uint8_t* account_id, uint32_t nonce, uint32_t count,
                         uint32_t total_scoops, std::vector<std::vector<uint8_t>>& results);

#endif
