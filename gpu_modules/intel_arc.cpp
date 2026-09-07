#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iostream>
#include <fstream>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <fstream>

// using intel level zero bc intel drivers are bad / require too much things (like one api)
#include <level_zero/ze_api.h>

struct IntelArcDevice {
    ze_device_handle_t device = nullptr;
    ze_context_handle_t context = nullptr;
    ze_command_queue_handle_t command_queue = nullptr;
    ze_module_handle_t module = nullptr;
    ze_kernel_handle_t kernel = nullptr;
    bool available = false;
    std::string name;
};

static std::mutex g_ze_mutex;
static IntelArcDevice g_ze_device;
static bool g_ze_initialized = false;

bool init_level_zero() {
    std::lock_guard<std::mutex> lock(g_ze_mutex);
    if (g_ze_initialized) return g_ze_device.available;

    ze_result_t result = zeInit(ZE_INIT_FLAG_GPU_ONLY);
    if (result != ZE_RESULT_SUCCESS) {
        std::cerr << "[ZE] zeInit failed: 0x" << std::hex << result << std::dec << std::endl;
        return false;
    }

    uint32_t driver_count = 0;
    result = zeDriverGet(&driver_count, nullptr);
    if (result != ZE_RESULT_SUCCESS || driver_count == 0) {
        std::cerr << "[ZE] No drivers found" << std::endl;
        return false;
    }

    std::vector<ze_driver_handle_t> drivers(driver_count);
    result = zeDriverGet(&driver_count, drivers.data());
    if (result != ZE_RESULT_SUCCESS) {
        std::cerr << "[ZE] zeDriverGet failed" << std::endl;
        return false;
    }

    ze_device_properties_t props = {};
    props.stype = ZE_STRUCTURE_TYPE_DEVICE_PROPERTIES;
    for (uint32_t d = 0; d < driver_count && !g_ze_device.device; ++d) {
        uint32_t count = 0;
        zeDeviceGet(drivers[d], &count, nullptr);
        if (count == 0) continue;
        std::vector<ze_device_handle_t> devices(count);
        zeDeviceGet(drivers[d], &count, devices.data());
        for (uint32_t i = 0; i < count; ++i) {
            zeDeviceGetProperties(devices[i], &props);
            if (props.type == ZE_DEVICE_TYPE_GPU) {
                g_ze_device.device = devices[i];
                g_ze_device.name = props.name;
                break;
            }
        }
    }

    if (!g_ze_device.device) {
        std::cerr << "[ZE] No GPU device found" << std::endl;
        return false;
    }

    ze_context_desc_t ctx_desc = {ZE_STRUCTURE_TYPE_CONTEXT_DESC, nullptr, 0};
    result = zeContextCreate(drivers[0], &ctx_desc, &g_ze_device.context);
    if (result != ZE_RESULT_SUCCESS) {
        std::cerr << "[ZE] zeContextCreate failed" << std::endl;
        return false;
    }

    ze_command_queue_desc_t cq_desc = {
        ZE_STRUCTURE_TYPE_COMMAND_QUEUE_DESC, nullptr, 0,
        ZE_COMMAND_QUEUE_MODE_DEFAULT, ZE_COMMAND_QUEUE_PRIORITY_NORMAL
    };
    result = zeCommandQueueCreate(g_ze_device.context, g_ze_device.device, &cq_desc, &g_ze_device.command_queue);
    if (result != ZE_RESULT_SUCCESS) {
        std::cerr << "[ZE] zeCommandQueueCreate failed" << std::endl;
        return false;
    }

    g_ze_device.available = true;
    std::cout << "[ZE] Intel Arc GPU initialized: " << g_ze_device.name << std::endl;
    return true;
}

void shutdown_level_zero() {
    std::lock_guard<std::mutex> lock(g_ze_mutex);
    if (g_ze_device.kernel) zeKernelDestroy(g_ze_device.kernel);
    if (g_ze_device.module) zeModuleDestroy(g_ze_device.module);
    if (g_ze_device.command_queue) zeCommandQueueDestroy(g_ze_device.command_queue);
    if (g_ze_device.context) zeContextDestroy(g_ze_device.context);
    g_ze_device = {};
    g_ze_initialized = false;
}

static const char* sha256_kernel_source = R"(
#define ROTR(x, n) ((x) >> (n) | (x) << (32 - (n)))
#define CH(x, y, z) ((x) ^ (y) ^ (z))
#define MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

__constant__ uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__kernel void sha256_batch(__global const uint8_t* inputs, __global uint8_t* outputs, uint32_t total_hashes) {
    uint32_t gid = get_global_id(0);
    if (gid >= total_hashes) return;

    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint32_t m[16];
    for (int i = 0; i < 16; ++i) {
        uint32_t idx = gid * 64 + i * 4;
        m[i] = (inputs[idx] << 24) | (inputs[idx + 1] << 16) | (inputs[idx + 2] << 8) | inputs[idx + 3];
    }

    for (int i = 16; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    uint32_t out_idx = gid * 32;
    for (int i = 0; i < 8; ++i) {
        outputs[out_idx + i * 4] = (state[i] >> 24) & 0xFF;
        outputs[out_idx + i * 4 + 1] = (state[i] >> 16) & 0xFF;
        outputs[out_idx + i * 4 + 2] = (state[i] >> 8) & 0xFF;
        outputs[out_idx + i * 4 + 3] = state[i] & 0xFF;
    }
}
)";

bool gpu_generate_scoops(const uint8_t* account_id, uint32_t nonce, uint32_t count,
                                 uint32_t total_scoops, std::vector<std::vector<uint8_t>>& results) {
    if (!g_ze_device.available) return false;

    ze_result_t result;

    std::string spv_path = std::string("/tmp/ze_kernel/sha256_pvc.spv");
    std::ifstream spv_file(spv_path, std::ios::binary);
    if (!spv_file) {
        std::cerr << "[ZE] Cannot open SPIR-V file: " << spv_path << std::endl;
        return false;
    }
    std::vector<uint8_t> spv_bytes((std::istreambuf_iterator<char>(spv_file)), std::istreambuf_iterator<char>());
    spv_file.close();

    ze_module_desc_t module_desc = {
        ZE_STRUCTURE_TYPE_MODULE_DESC, nullptr,
        ZE_MODULE_FORMAT_IL_SPIRV, spv_bytes.size(),
        spv_bytes.data(), nullptr, nullptr
    };
    result = zeModuleCreate(g_ze_device.context, g_ze_device.device, &module_desc, &g_ze_device.module, nullptr);
    if (result != ZE_RESULT_SUCCESS) {
        std::cerr << "[ZE] zeModuleCreate failed: 0x" << std::hex << result << std::dec << std::endl;
        return false;
    }

    ze_kernel_desc_t kernel_desc = {
        ZE_STRUCTURE_TYPE_KERNEL_DESC, nullptr, 0, "sha256_batch"
    };
    result = zeKernelCreate(g_ze_device.module, &kernel_desc, &g_ze_device.kernel);
    if (result != ZE_RESULT_SUCCESS) {
        std::cerr << "[ZE] zeKernelCreate failed" << std::endl;
        return false;
    }

    uint32_t base_nonce = nonce;
    uint32_t num_workitems = count;
    size_t input_size = num_workitems * 64;
    size_t output_size = num_workitems * 32;

    ze_device_mem_alloc_desc_t alloc_desc = {ZE_STRUCTURE_TYPE_DEVICE_MEM_ALLOC_DESC, nullptr, 0, 0};
    void* d_input = nullptr;
    void* d_output = nullptr;
    result = zeMemAllocDevice(g_ze_device.context, &alloc_desc, input_size, 64, g_ze_device.device, &d_input);
    if (result != ZE_RESULT_SUCCESS) { std::cerr << "[ZE] alloc input failed" << std::endl; return false; }
    result = zeMemAllocDevice(g_ze_device.context, &alloc_desc, output_size, 64, g_ze_device.device, &d_output);
    if (result != ZE_RESULT_SUCCESS) { std::cerr << "[ZE] alloc output failed" << std::endl; return false; }

    std::vector<uint8_t> h_input(input_size);
    std::vector<uint8_t> h_output(output_size);
    for (uint32_t i = 0; i < num_workitems; ++i) {
        uint32_t n = base_nonce + i;
        memcpy(h_input.data() + i * 64, account_id, 32);
        memcpy(h_input.data() + i * 64 + 32, &n, 4);
        memset(h_input.data() + i * 64 + 36, 0, 28);
    }

    ze_command_list_handle_t cmd_list = nullptr;
    ze_command_list_desc_t cmd_desc = {ZE_STRUCTURE_TYPE_COMMAND_LIST_DESC, nullptr, 0};
    zeCommandListCreate(g_ze_device.context, g_ze_device.device, &cmd_desc, &cmd_list);
    zeCommandListAppendMemoryCopy(cmd_list, d_input, h_input.data(), input_size, nullptr, 0, nullptr);
    zeCommandListAppendBarrier(cmd_list, nullptr, 0, nullptr);
    zeCommandListClose(cmd_list);
    zeCommandQueueExecuteCommandLists(g_ze_device.command_queue, 1, &cmd_list, nullptr);
    zeCommandQueueSynchronize(g_ze_device.command_queue, UINT64_MAX);
    zeCommandListDestroy(cmd_list);

    zeKernelSetArgumentValue(g_ze_device.kernel, 0, sizeof(void*), &d_input);
    zeKernelSetArgumentValue(g_ze_device.kernel, 1, sizeof(void*), &d_output);
    zeKernelSetArgumentValue(g_ze_device.kernel, 2, sizeof(uint32_t), &num_workitems);

    ze_group_count_t group_count = {(num_workitems + 63) / 64, 1, 1};
    zeCommandListCreate(g_ze_device.context, g_ze_device.device, &cmd_desc, &cmd_list);
    zeCommandListAppendLaunchKernel(cmd_list, g_ze_device.kernel, &group_count, nullptr, 0, nullptr);
    zeCommandListAppendMemoryCopy(cmd_list, h_output.data(), d_output, output_size, nullptr, 0, nullptr);
    zeCommandListClose(cmd_list);
    zeCommandQueueExecuteCommandLists(g_ze_device.command_queue, 1, &cmd_list, nullptr);
    zeCommandQueueSynchronize(g_ze_device.command_queue, UINT64_MAX);
    zeCommandListDestroy(cmd_list);

    results.clear();
    results.resize(num_workitems);
    for (uint32_t i = 0; i < num_workitems; ++i) {
        results[i].resize(32);
        memcpy(results[i].data(), h_output.data() + i * 32, 32);
    }

    zeMemFree(g_ze_device.context, d_input);
    zeMemFree(g_ze_device.context, d_output);

    return true;
}

bool is_intel_arc_available() {
    return init_level_zero();
}

void shutdown_intel_arc() {
    shutdown_level_zero();
}
