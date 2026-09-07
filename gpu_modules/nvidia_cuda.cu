#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iostream>

#include <cuda_runtime.h>

#include "nvidia_cuda.h"

// =====================================================================
// NVIDIA CUDA GPU plotting module
// Port of the Intel Arc / Level Zero backend (intel_arc.cpp) to CUDA.
// =====================================================================

struct NvidiaCudaDevice {
    int device_id = -1;
    bool available = false;
    std::string name;
};

static std::mutex g_cuda_mutex;
static NvidiaCudaDevice g_cuda_device;
static bool g_cuda_initialized = false;

#define CUDA_CHECK_RET(call, retval) do { \
    cudaError_t _err = (call); \
    if (_err != cudaSuccess) { \
        std::cerr << "[CUDA] " #call " failed: " << cudaGetErrorString(_err) << std::endl; \
        return retval; \
    } \
} while (0)

bool init_cuda() {
    std::lock_guard<std::mutex> lock(g_cuda_mutex);
    if (g_cuda_initialized) return g_cuda_device.available;
    g_cuda_initialized = true;

    int device_count = 0;
    cudaError_t err = cudaGetDeviceCount(&device_count);
    if (err != cudaSuccess || device_count == 0) {
        std::cerr << "[CUDA] No CUDA devices found" << std::endl;
        return false;
    }

    // Pick device 0 (could be extended to pick the best by compute capability/mem).
    int chosen = 0;
    cudaDeviceProp props{};
    err = cudaGetDeviceProperties(&props, chosen);
    if (err != cudaSuccess) {
        std::cerr << "[CUDA] cudaGetDeviceProperties failed" << std::endl;
        return false;
    }

    err = cudaSetDevice(chosen);
    if (err != cudaSuccess) {
        std::cerr << "[CUDA] cudaSetDevice failed" << std::endl;
        return false;
    }

    g_cuda_device.device_id = chosen;
    g_cuda_device.name = props.name;
    g_cuda_device.available = true;

    std::cout << "[CUDA] NVIDIA GPU initialized: " << g_cuda_device.name
               << " (SM " << props.major << "." << props.minor << ")" << std::endl;
    return true;
}

void shutdown_cuda() {
    std::lock_guard<std::mutex> lock(g_cuda_mutex);
    if (g_cuda_device.available) {
        cudaDeviceReset();
    }
    g_cuda_device = {};
    g_cuda_initialized = false;
}

// ---------------------------------------------------------------------
// SHA-256 CUDA kernel (device-side port of the Level Zero OpenCL-style kernel)
// ---------------------------------------------------------------------

__device__ __constant__ uint32_t d_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ __forceinline__ uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}
#define D_CH(x, y, z) ((x) ^ (y) ^ (z))
#define D_MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define D_EP0(x) (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define D_EP1(x) (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define D_SIG0(x) (rotr(x, 7) ^ rotr(x, 18) ^ ((x) >> 3))
#define D_SIG1(x) (rotr(x, 17) ^ rotr(x, 19) ^ ((x) >> 10))

__global__ void sha256_batch_kernel(const uint8_t* __restrict__ inputs,
                                     uint8_t* __restrict__ outputs,
                                     uint32_t total_hashes) {
    uint32_t gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= total_hashes) return;

    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint32_t m[64];
    const uint8_t* in = inputs + (size_t)gid * 64;
#pragma unroll
    for (int i = 0; i < 16; ++i) {
        uint32_t idx = i * 4;
        m[i] = (in[idx] << 24) | (in[idx + 1] << 16) | (in[idx + 2] << 8) | in[idx + 3];
    }

#pragma unroll
    for (int i = 16; i < 64; ++i) {
        m[i] = D_SIG1(m[i - 2]) + m[i - 7] + D_SIG0(m[i - 15]) + m[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

#pragma unroll
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + D_EP1(e) + D_CH(e, f, g) + d_k[i] + m[i];
        uint32_t t2 = D_EP0(a) + D_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    uint8_t* out = outputs + (size_t)gid * 32;
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = (state[i] >> 24) & 0xFF;
        out[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        out[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        out[i * 4 + 3] = state[i] & 0xFF;
    }
}

// ---------------------------------------------------------------------
// Host-side batch entry point — same signature/semantics as the
// Intel Arc version so plotter.cpp can call it interchangeably.
// ---------------------------------------------------------------------
bool cuda_generate_scoops(const uint8_t* account_id, uint32_t nonce, uint32_t count,
                           uint32_t total_scoops, std::vector<std::vector<uint8_t>>& results) {
    if (!g_cuda_device.available) return false;

    uint32_t base_nonce = nonce;
    uint32_t num_workitems = count;
    size_t input_size = (size_t)num_workitems * 64;
    size_t output_size = (size_t)num_workitems * 32;

    std::vector<uint8_t> h_input(input_size);
    std::vector<uint8_t> h_output(output_size);
    for (uint32_t i = 0; i < num_workitems; ++i) {
        uint32_t n = base_nonce + i;
        memcpy(h_input.data() + (size_t)i * 64, account_id, 32);
        memcpy(h_input.data() + (size_t)i * 64 + 32, &n, 4);
        memset(h_input.data() + (size_t)i * 64 + 36, 0, 28);
    }

    uint8_t* d_input = nullptr;
    uint8_t* d_output = nullptr;
    CUDA_CHECK_RET(cudaMalloc(&d_input, input_size), false);
    CUDA_CHECK_RET(cudaMalloc(&d_output, output_size), false);

    CUDA_CHECK_RET(cudaMemcpy(d_input, h_input.data(), input_size, cudaMemcpyHostToDevice), false);

    const int threads_per_block = 256;
    const int blocks = (num_workitems + threads_per_block - 1) / threads_per_block;
    sha256_batch_kernel<<<blocks, threads_per_block>>>(d_input, d_output, num_workitems);

    cudaError_t launch_err = cudaGetLastError();
    if (launch_err != cudaSuccess) {
        std::cerr << "[CUDA] kernel launch failed: " << cudaGetErrorString(launch_err) << std::endl;
        cudaFree(d_input);
        cudaFree(d_output);
        return false;
    }

    CUDA_CHECK_RET(cudaDeviceSynchronize(), false);
    CUDA_CHECK_RET(cudaMemcpy(h_output.data(), d_output, output_size, cudaMemcpyDeviceToHost), false);

    results.clear();
    results.resize(num_workitems);
    for (uint32_t i = 0; i < num_workitems; ++i) {
        results[i].resize(32);
        memcpy(results[i].data(), h_output.data() + (size_t)i * 32, 32);
    }

    cudaFree(d_input);
    cudaFree(d_output);

    return true;
}

bool is_nvidia_cuda_available() {
    return init_cuda();
}

void shutdown_nvidia_cuda() {
    shutdown_cuda();
}

const char* nvidia_cuda_device_name() {
    return g_cuda_device.name.c_str();
}
