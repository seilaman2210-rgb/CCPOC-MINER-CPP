#ifndef NVIDIA_CUDA_H
#define NVIDIA_CUDA_H

#include <vector>
#include <cstdint>

bool is_nvidia_cuda_available();
void shutdown_nvidia_cuda();
const char* nvidia_cuda_device_name();
bool cuda_generate_scoops(const uint8_t* account_id, uint32_t nonce, uint32_t count,
                           uint32_t total_scoops, std::vector<std::vector<uint8_t>>& results);

#endif
