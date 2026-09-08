#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/statvfs.h>
#include <json-c/json.h>
#include <openssl/sha.h>

const uint32_t SCOOP_SIZE = 32;
const uint32_t SCOOPS_PER_NONCE = 8192;
const uint32_t MINING_SCOOP_MODULUS = 4096;
const uint32_t HEADER_SIZE = 256;
const uint32_t PLOT_FORMAT_V3 = 3;
const uint32_t CHUNK_PAIRS = 256 * 1024;
const uint32_t WRIT_BATCH_NONCES = 4000;
const uint32_t ZERO_HASH_LEN = 64;

const char* PLOT_MAGIC = "CHOCOHUB";

const double EFFECTIVE_CAPACITY_CAP_GB = 10 * 1024.0;

static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::string hex(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        sprintf(&hex[i * 2], "%02x", data[i]);
    }
    return hex;
}

static std::string bytes_to_hex(const std::vector<uint8_t>& v) {
    return bytes_to_hex(v.data(), v.size());
}

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve((hex.size() + 1) / 2);
    size_t start = 0;
    if (hex.size() > 0 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) start = 2;
    for (size_t i = start; i < hex.size(); i += 2) {
        unsigned int byte = 0;
        if (i + 1 < hex.size()) {
            sscanf(&hex[i], "%02x", &byte);
        } else {
            sscanf(&hex[i], "%01x", &byte);
        }
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
}

static std::vector<uint8_t> base64_decode(const std::string& b64) {
    std::vector<uint8_t> out;
    size_t len = b64.size();
    out.reserve(len * 3 / 4 + 4);
    const char* p = b64.c_str();
    while (*p) {
        while (*p && isspace(*p)) ++p;
        if (!*p) break;
        unsigned int val = 0;
        int bits = 0;
        for (int i = 0; i < 4 && *p; ++p) {
            unsigned char c = *p;
            if (c == '=') break;
            if (isspace(c)) continue;
            int digit = -1;
            if (c >= 'A' && c <= 'Z') digit = c - 'A';
            else if (c >= 'a' && c <= 'z') digit = c - 'a' + 26;
            else if (c >= '0' && c <= '9') digit = c - '0' + 52;
            else if (c == '+' || c == '-') digit = 62;
            else if (c == '/' || c == '_') digit = 63;
            if (digit < 0) continue;
            val = (val << 6) | digit;
            bits += 6;
            ++i;
        }
        while (bits >= 8) {
            out.push_back(static_cast<uint8_t>((val >> (bits - 8)) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

struct WalletData {
    std::string path;
    std::string address;
    std::string public_key_b64;
    std::string private_key_hex;
    std::vector<uint8_t> public_key_bytes;
    std::vector<uint8_t> private_key_bytes;
    bool loaded = false;
};

static bool load_wallet_file(const std::string& path, WalletData& wallet) {
    std::ifstream f(path);
    if (!f) return false;
    std::string json_str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();

    json_object* jobj = json_tokener_parse(json_str.c_str());
    if (!jobj) return false;

    wallet.path = path;
    wallet.loaded = true;

    json_object* j;
    if (json_object_object_get_ex(jobj, "address", &j)) {
        wallet.address = json_object_get_string(j);
    }
    if (json_object_object_get_ex(jobj, "public_key", &j)) {
        wallet.public_key_b64 = json_object_get_string(j);
        wallet.public_key_bytes = base64_decode(wallet.public_key_b64);
    } else if (json_object_object_get_ex(jobj, "publicKey", &j)) {
        std::string pub_hex = json_object_get_string(j);
        wallet.public_key_bytes = hex_to_bytes(pub_hex);
        wallet.public_key_b64 = bytes_to_hex(wallet.public_key_bytes);
    }
    if (json_object_object_get_ex(jobj, "private_key", &j)) {
        wallet.private_key_hex = json_object_get_string(j);
        wallet.private_key_bytes = hex_to_bytes(wallet.private_key_hex);
    } else if (json_object_object_get_ex(jobj, "privateKey", &j)) {
        wallet.private_key_hex = json_object_get_string(j);
        wallet.private_key_bytes = hex_to_bytes(wallet.private_key_hex);
    }

    json_object_put(jobj);
    return wallet.loaded;
}

static std::string sha256_hex(const uint8_t* data, size_t len) {
    uint8_t md[SHA256_DIGEST_LENGTH];
    SHA256(data, len, md);
    char hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hex + i * 2, "%02x", md[i]);
    }
    hex[SHA256_DIGEST_LENGTH * 2] = '\0';
    return std::string(hex);
}

static std::string sha256_hex(const std::string& s) {
    return sha256_hex(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

static std::string sha256_hex(const std::vector<uint8_t>& v) {
    return sha256_hex(v.data(), v.size());
}

static std::vector<uint8_t> sha256_buf(const uint8_t* data, size_t len) {
    std::vector<uint8_t> md(SHA256_DIGEST_LENGTH);
    SHA256(data, len, md.data());
    return md;
}

static std::vector<uint8_t> sha256_buf(const std::string& s) {
    return sha256_buf(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

static std::vector<uint8_t> sha256_buf(const std::vector<uint8_t>& v) {
    return sha256_buf(v.data(), v.size());
}

static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    return sha256_buf(data);
}

static std::vector<uint8_t> sha256(const uint8_t* data, size_t len) {
    return sha256_buf(data, len);
}

static std::vector<uint8_t> resolve_account_id(const WalletData& wallet) {
    if (!wallet.loaded) {
        std::vector<uint8_t> random(32);
        for (size_t i = 0; i < 32; ++i) random[i] = rand() % 256;
        return random;
    }
    if (!wallet.public_key_bytes.empty()) {
        return sha256(wallet.public_key_bytes);
    }
    std::vector<uint8_t> random(32);
    for (size_t i = 0; i < 32; ++i) random[i] = rand() % 256;
    return random;
}

static std::string resolve_miner_address(const WalletData& wallet) {
    if (!wallet.loaded || wallet.address.empty()) {
        return "0x0000000000000000000000000000000000000000";
    }
    return wallet.address;
}

struct PlotMeta {
    uint32_t plot_id_high;
    uint32_t plot_id_low;
    std::string miner_address;
    uint32_t total_scoops;
    uint32_t scoop_size;
    std::string merkle_root;
    std::vector<uint8_t> account_id;
    uint64_t first_nonce;
};

static uint64_t merkle_tree_internal_node_count(uint64_t n) {
    uint64_t total = 0;
    while (n > 1) {
        n = (n + 1) / 2;
        total += n;
    }
    return total;
}

static uint64_t plot_total_size(uint64_t total_scoops) {
    return HEADER_SIZE + total_scoops * SCOOP_SIZE + merkle_tree_internal_node_count(total_scoops) * 32;
}

static uint32_t plot_scoop_count(double size_gb) {
    return std::max<uint32_t>(1, static_cast<uint32_t>((size_gb * 1024.0 * 1024.0 * 1024.0) / SCOOP_SIZE));
}

static std::vector<uint8_t> generate_v3_scoops_abs(const std::vector<uint8_t>& account_id,
                                                   uint64_t first_nonce,
                                                   uint64_t scoop_start,
                                                   uint32_t count) {
    std::vector<uint8_t> result(count * 32);
    std::vector<uint8_t> base(32);
    std::vector<uint8_t> combined(36);
    uint32_t out_i = 0;
    uint64_t g = scoop_start;
    const uint64_t end = scoop_start + count;
    uint64_t last_nonce = UINT64_MAX;
    while (g < end) {
        uint64_t nonce_val = first_nonce + g / SCOOPS_PER_NONCE;
        if (nonce_val != last_nonce) {
            uint32_t nb[1] = { static_cast<uint32_t>(nonce_val) };
            std::vector<uint8_t> base_input;
            base_input.reserve(account_id.size() + 4);
            base_input.insert(base_input.end(), account_id.begin(), account_id.end());
            base_input.insert(base_input.end(),
                              reinterpret_cast<uint8_t*>(nb),
                              reinterpret_cast<uint8_t*>(nb) + 4);
            base = sha256(base_input);
            last_nonce = nonce_val;
        }
        uint32_t offset_in_nonce = static_cast<uint32_t>(g % SCOOPS_PER_NONCE);
        uint64_t take = std::min<uint64_t>(SCOOPS_PER_NONCE - offset_in_nonce, end - g);
        for (uint64_t j = 0; j < take; ++j) {
            memcpy(combined.data(), base.data(), 32);
            uint32_t idxv = offset_in_nonce + static_cast<uint32_t>(j);
            combined[32] = idxv & 0xFF;
            combined[33] = (idxv >> 8) & 0xFF;
            combined[34] = (idxv >> 16) & 0xFF;
            combined[35] = (idxv >> 24) & 0xFF;
            std::vector<uint8_t> hash = sha256(combined);
            memcpy(result.data() + out_i++ * 32, hash.data(), 32);
        }
        g += take;
    }
    return result;
}

static std::vector<uint8_t> generate_v3_scoops(const std::vector<uint8_t>& account_id, uint32_t nonce, uint32_t count) {
    uint32_t nonce_bytes[1];
    nonce_bytes[0] = nonce;
    std::vector<uint8_t> nonce_vec(reinterpret_cast<uint8_t*>(nonce_bytes), reinterpret_cast<uint8_t*>(nonce_bytes) + 4);

    std::vector<uint8_t> base_input;
    base_input.reserve(account_id.size() + 4);
    base_input.insert(base_input.end(), account_id.begin(), account_id.end());
    base_input.insert(base_input.end(), nonce_vec.begin(), nonce_vec.end());

    std::vector<uint8_t> base = sha256(base_input);

    std::vector<uint8_t> result(count * 32);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t idx_bytes[1] = {i};
        std::vector<uint8_t> idx_vec(reinterpret_cast<uint8_t*>(idx_bytes), reinterpret_cast<uint8_t*>(idx_bytes) + 4);

        std::vector<uint8_t> combined;
        combined.reserve(base.size() + 4);
        combined.insert(combined.end(), base.begin(), base.end());
        combined.insert(combined.end(), idx_vec.begin(), idx_vec.end());

        std::vector<uint8_t> hash = sha256(combined);
        memcpy(result.data() + i * 32, hash.data(), 32);
    }
    return result;
}

static std::vector<uint8_t> generate_scoops_chunk(const std::vector<uint8_t>& account_id, uint32_t nonce_start, uint32_t nonce_end, uint64_t total_scoops, uint64_t first_nonce) {
    std::vector<uint8_t> parts;
    for (uint32_t n = nonce_start; n < nonce_end; ++n) {
        uint32_t nonce_scoops = std::min<uint64_t>(SCOOPS_PER_NONCE, total_scoops - static_cast<uint64_t>(n) * SCOOPS_PER_NONCE);
        if (nonce_scoops == 0) break;
        auto scoop_data = generate_v3_scoops(account_id, static_cast<uint32_t>(first_nonce + n), nonce_scoops);
        parts.insert(parts.end(), scoop_data.begin(), scoop_data.end());
    }
    return parts;
}

static uint64_t stream_level(const std::string& in_path, const std::string& out_path, uint64_t count, int workers) {
    uint64_t new_len = (count + 1) / 2;
    const uint64_t CHUNK = 256 * 1024;

    std::ifstream inp(in_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    if (!inp || !out) {
        std::cerr << "[MERK] Cannot open files for level" << std::endl;
        return 0;
    }

    uint64_t pairs_done = 0;
    inp.seekg(0, std::ios::beg);
    while (pairs_done < new_len) {
        uint64_t need = std::min(CHUNK, new_len - pairs_done);
        std::vector<uint8_t> raw(need * 64);
        inp.read(reinterpret_cast<char*>(raw.data()), need * 64);
        size_t got = inp.gcount();
        if (got < need * 64 && got >= 32) {
            size_t needed = need * 64 - got;
            size_t tail_start = (got >= 32) ? got - 32 : 0;
            size_t tail_len = (got >= 32) ? 32 : got;
            for (size_t i = 0; i < needed / 32; ++i) {
                memcpy(raw.data() + got + i * 32, raw.data() + tail_start, tail_len);
            }
        }
        std::vector<uint8_t> result(need * 32);
        for (uint64_t i = 0; i < need; ++i) {
            std::vector<uint8_t> left(raw.data() + i * 64, raw.data() + i * 64 + 32);
            std::vector<uint8_t> right(raw.data() + i * 64 + 32, raw.data() + i * 64 + 64);
            std::vector<uint8_t> combined;
            combined.reserve(64);
            combined.insert(combined.end(), left.begin(), left.end());
            combined.insert(combined.end(), right.begin(), right.end());
            std::vector<uint8_t> hash = sha256(combined);
            memcpy(result.data() + i * 32, hash.data(), 32);
        }
        out.write(reinterpret_cast<const char*>(result.data()), result.size());
        pairs_done += need;
    }
    return new_len;
}

static void log_progress(const std::string& stage, uint64_t current, uint64_t total, double elapsed = 0.0, double total_bytes = 0.0) {
    int pct = total > 0 ? std::min(100, std::max(0, static_cast<int>((current * 100) / total))) : 100;
    int width = 32;
    int filled = static_cast<int>((pct / 100.0) * width);
    std::string bar(filled, '#');
    bar.append(width - filled, '-');

    std::cout << "\r  [" << stage << "] [" << bar << "] " << std::setw(3) << pct << "%";
    if (stage == "WRIT" && total_bytes > 0 && elapsed > 0.5) {
        double mb_per_sec = (total_bytes * pct / 100.0) / elapsed / 1e6;
        std::cout << " | " << std::fixed << std::setprecision(1) << mb_per_sec << " MB/s";
        if (pct < 100 && pct > 0) {
            double remaining = (elapsed / pct) * (100 - pct);
            if (remaining > 0) {
                int m = static_cast<int>(remaining / 60);
                int s = static_cast<int>(fmod(remaining, 60));
                std::cout << " | ETA " << m << "m" << s << "s";
            }
        }
    } else if (elapsed > 0.5 && current > 0) {
        double rate = current / elapsed;
        std::cout << " | " << std::fixed << std::setprecision(0) << rate << " items/s";
        if (pct < 100 && pct > 0) {
            double remaining = (elapsed / pct) * (100 - pct);
            if (remaining > 0) {
                int m = static_cast<int>(remaining / 60);
                int s = static_cast<int>(fmod(remaining, 60));
                std::cout << " | ETA " << m << "m" << s << "s";
            }
        }
    }
    std::cout << std::flush;
}

static std::string checkpoint_path(const std::string& plot_path) {
    return plot_path + ".plot_checkpoint";
}

static void save_checkpoint(const std::string& plot_path, const std::string& stage, uint64_t last_scoop, int level) {
    std::string cp = checkpoint_path(plot_path);
    std::ofstream f(cp);
    if (f) {
        f << stage << "\n" << last_scoop << "\n" << level << "\n";
    }
}

static bool load_checkpoint(const std::string& plot_path, std::string& stage, uint64_t& last_scoop, int& level) {
    std::string cp = checkpoint_path(plot_path);
    std::ifstream f(cp);
    if (!f) return false;
    std::string line;
    if (!std::getline(f, line)) return false;
    stage = line;
    if (!std::getline(f, line)) return false;
    last_scoop = std::stoull(line);
    if (!std::getline(f, line)) line = "0";
    level = std::stoi(line);
    return true;
}

static void clear_checkpoint(const std::string& plot_path) {
    std::string cp = checkpoint_path(plot_path);
    std::remove(cp.c_str());
}

static bool check_disk_space(const std::string& plot_path, uint64_t required_bytes) {
    struct stat st;
    if (stat(plot_path.c_str(), &st) != 0) {
        std::string dir = plot_path.substr(0, plot_path.find_last_of("/\\"));
        if (dir.empty()) dir = ".";
        if (stat(dir.c_str(), &st) != 0) return true;
    }
    struct statvfs sv;
    if (statvfs(".", &sv) != 0) return true;
    uint64_t free = sv.f_frsize * sv.f_bavail;
    if (free < required_bytes) {
        std::cerr << "[DISK] Not enough space: free=" << free / 1e9 << " GB, need=" << required_bytes / 1e9 << " GB" << std::endl;
        return false;
    }
    return true;
}

static bool read_plot_meta(const std::string& path, PlotMeta& meta) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    std::vector<uint8_t> header(HEADER_SIZE);
    f.read(reinterpret_cast<char*>(header.data()), HEADER_SIZE);
    if (f.gcount() < static_cast<std::streamsize>(104)) return false;

    if (memcmp(header.data(), PLOT_MAGIC, 8) != 0) return false;

    uint32_t version = *reinterpret_cast<const uint32_t*>(header.data() + 8);
    meta.plot_id_high = *reinterpret_cast<const uint32_t*>(header.data() + 12);
    meta.plot_id_low = *reinterpret_cast<const uint32_t*>(header.data() + 16);
    meta.miner_address.assign(reinterpret_cast<const char*>(header.data() + 20), 44);
    meta.total_scoops = *reinterpret_cast<const uint32_t*>(header.data() + 64);
    meta.scoop_size = *reinterpret_cast<const uint32_t*>(header.data() + 68);
    meta.merkle_root.assign(reinterpret_cast<const char*>(header.data() + 72), 32);

    if (version == 3) {
        meta.account_id.assign(header.begin() + 104, header.begin() + 136);
        meta.first_nonce = *reinterpret_cast<const uint64_t*>(header.data() + 136);
    }

    size_t null_pos = meta.miner_address.find('\0');
    if (null_pos != std::string::npos) meta.miner_address.resize(null_pos);

    return meta.total_scoops >= 1;
}

static std::string plot_id_string(const PlotMeta& meta) {
    char buf[17];
    sprintf(buf, "%08x%08x", meta.plot_id_high, meta.plot_id_low);
    return std::string(buf);
}

static std::vector<uint8_t> choose_first_nonce(const std::string& plot_dir, const std::vector<uint8_t>& account_id, uint64_t total_scoops) {
    uint64_t needed = (total_scoops + SCOOPS_PER_NONCE - 1) / SCOOPS_PER_NONCE;

    std::vector<std::pair<uint64_t, uint64_t>> used;
    DIR* dp = opendir(plot_dir.c_str());
    if (dp) {
        struct dirent* entry;
        while ((entry = readdir(dp)) != nullptr) {
            std::string name = entry->d_name;
            if (name.size() < 5 || name.substr(name.size() - 5) != ".plot") continue;
            std::string full = plot_dir + "/" + name;
            PlotMeta pm;
            if (!read_plot_meta(full, pm)) continue;
            if (!account_id.empty() && !pm.account_id.empty() && pm.account_id != account_id) continue;
            uint64_t fn = pm.first_nonce;
            uint64_t nonces = (pm.total_scoops + SCOOPS_PER_NONCE - 1) / SCOOPS_PER_NONCE;
            used.emplace_back(fn, fn + nonces);
        }
        closedir(dp);
    }

    uint64_t space = std::max(needed + 1, static_cast<uint64_t>(0x100000000) - needed);
    for (int i = 0; i < 100; ++i) {
        uint64_t cand = rand() % space;
        bool overlap = false;
        for (const auto& r : used) {
            if (cand >= r.first && cand < r.second) {
                overlap = true;
                break;
            }
        }
        if (!overlap) {
            return {(uint8_t)(cand & 0xFF), (uint8_t)((cand >> 8) & 0xFF),
                    (uint8_t)((cand >> 16) & 0xFF), (uint8_t)((cand >> 24) & 0xFF)};
        }
    }
    uint64_t max_end = 0;
    for (const auto& r : used) max_end = std::max(max_end, r.second);
    uint64_t result = max_end;
    return {(uint8_t)(result & 0xFF), (uint8_t)((result >> 8) & 0xFF),
            (uint8_t)((result >> 16) & 0xFF), (uint8_t)((result >> 24) & 0xFF)};
}

static std::vector<uint8_t> uint32_to_le(uint32_t v) {
    return {static_cast<uint8_t>(v & 0xFF), static_cast<uint8_t>((v >> 8) & 0xFF),
            static_cast<uint8_t>((v >> 16) & 0xFF), static_cast<uint8_t>((v >> 24) & 0xFF)};
}

static std::vector<uint8_t> uint64_to_le(uint64_t v) {
    std::vector<uint8_t> b(8);
    for (int i = 0; i < 8; ++i) b[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
    return b;
}

static bool create_plot_file(const std::string& plot_path, const std::string& plot_id,
                              const std::string& miner_address, double size_gb,
                              const std::vector<uint8_t>& account_id, bool progress = true,
                              bool resume = false) {
    uint32_t total_scoops = plot_scoop_count(size_gb);
    if (total_scoops < 1) {
        std::cerr << "[PLOT] Invalid size" << std::endl;
        return false;
    }
    if (total_scoops > 0xFFFFFFFF) {
        double max_gb = (static_cast<double>(0xFFFFFFFF) * SCOOP_SIZE) / (1024.0 * 1024.0 * 1024.0);
        std::cerr << "[PLOT] Plot size too large for v3 format: max ~" << max_gb << " GB" << std::endl;
        return false;
    }

    uint64_t plot_size = plot_total_size(total_scoops);
    if (!check_disk_space(plot_path, static_cast<uint64_t>(plot_size * 1.3))) return false;

    std::string plot_dir = plot_path.substr(0, plot_path.find_last_of("/\\"));
    if (plot_dir.empty()) plot_dir = ".";
    std::vector<uint8_t> account = account_id.empty() ? std::vector<uint8_t>(32, 0) : account_id;

    std::vector<uint8_t> first_nonce_bytes = choose_first_nonce(plot_dir, account, total_scoops);
    uint64_t first_nonce = 0;
    for (int i = 0; i < 4; ++i) first_nonce |= static_cast<uint64_t>(first_nonce_bytes[i]) << (i * 8);

    std::cout << "[PLOT] Plot ID: " << plot_id << ", Miner: " << miner_address
              << ", Account: " << sha256_hex(account).substr(0, 16) << "..."
              << ", first_nonce=" << first_nonce << std::endl;
    std::cout << "[PLOT] Total scoops: " << total_scoops << ", File size: " << std::fixed << std::setprecision(2)
              << (plot_size / 1e9) << " GB" << std::endl;

    std::string start_stage;
    uint64_t start_scoop = 0;
    int start_level = 0;
    bool has_checkpoint = false;
    if (resume) {
        has_checkpoint = load_checkpoint(plot_path, start_stage, start_scoop, start_level);
        if (has_checkpoint) {
            std::cout << "[PLOT] Resuming from stage " << start_stage << ", scoop " << start_scoop << ", level " << start_level << std::endl;
        }
    }
    if (!has_checkpoint) clear_checkpoint(plot_path);

    auto t0 = std::chrono::high_resolution_clock::now();

    int workers = std::thread::hardware_concurrency();
    if (workers < 1) workers = 1;
    workers = std::min(workers, 64);

    std::string leaf_path = plot_path + ".tmp.leaf";
    std::string merkle_out_path = plot_path + ".tmp.merkle_all";

    if (start_stage.empty() || start_stage == "HASH") {
        std::cout << "  [HASH] Computing SHA-256 leaf hashes..." << std::endl;
        uint64_t leaf_count = (start_stage == "HASH") ? start_scoop : 0;
        if (start_stage == "HASH" && std::ifstream(leaf_path)) {
            uint64_t expected = leaf_count * SCOOP_SIZE;
            struct stat st;
            if (stat(leaf_path.c_str(), &st) == 0 && static_cast<uint64_t>(st.st_size) != expected) {
                std::ofstream trunc(leaf_path, std::ios::binary);
                trunc.close();
            }
        }

        const uint32_t BATCH = 500000;
        int last_log = -1;

        std::ofstream lf(leaf_path, leaf_count > 0 ? std::ios::binary | std::ios::app : std::ios::binary);
        while (leaf_count < total_scoops) {
            uint32_t batch = static_cast<uint32_t>(std::min<uint64_t>(BATCH, total_scoops - leaf_count));

            uint32_t chunk_size = std::max<uint32_t>(1, batch / workers);

            std::vector<std::thread> threads;
            std::vector<std::vector<uint8_t>> results(workers);
            for (int w = 0; w < workers; ++w) {
                uint32_t offset = w * chunk_size;
                uint32_t cs = (w < workers - 1) ? chunk_size : (batch - offset);
                if (cs == 0) break;
                threads.emplace_back([&, w, offset, cs]() {
                    results[w] = generate_v3_scoops_abs(account, first_nonce, leaf_count + offset, cs);
                });
            }
            for (auto& t : threads) t.join();

            for (int w = 0; w < workers && w < results.size(); ++w) {
                if (!results[w].empty()) lf.write(reinterpret_cast<const char*>(results[w].data()), results[w].size());
            }

            leaf_count += batch;

            if (progress) {
                int pct = static_cast<int>((leaf_count * 100) / total_scoops);
                if (pct >= last_log + 1) {
                    last_log = pct;
                    double elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::high_resolution_clock::now() - t0).count() / 1000.0;
                    log_progress("HASH", leaf_count, total_scoops, elapsed);
                }
            }
            if (leaf_count % ((total_scoops / 20) + 1) < batch) {
                save_checkpoint(plot_path, "HASH", leaf_count, 0);
            }
        }
        lf.close();
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "\n  [HASH] 100% done (" << std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count() / 1000.0 << "s)" << std::endl;
        clear_checkpoint(plot_path);
    } else {
        if (!std::ifstream(leaf_path)) {
            std::cerr << "[PLOT] Resume required but leaf file missing" << std::endl;
            return false;
        }
    }

    std::string root_hex;
    std::vector<uint8_t> root_bytes(32);
    if (start_stage.empty() || start_stage == "HASH" || start_stage == "MERK") {
        if (!std::ifstream(leaf_path)) {
            std::cerr << "[PLOT] Leaf file missing, cannot resume MERK" << std::endl;
            return false;
        }
        std::cout << "  [MERK] Building merkle tree..." << std::endl;
        uint64_t current_count = total_scoops;
        std::string input_path = leaf_path;

        int level = 0;
        auto t1 = std::chrono::high_resolution_clock::now();

        std::ofstream mf(merkle_out_path, std::ios::binary);
        while (current_count > 1) {
            if (start_stage == "MERK" && level < start_level) {
                uint64_t new_len = (current_count + 1) / 2;
                std::string out_path = plot_path + ".tmp.merk" + std::to_string(level);
                if (std::ifstream(out_path)) {
                    input_path = out_path;
                } else {
                    std::cerr << "[PLOT] Missing merkle file " << out_path << std::endl;
                    return false;
                }
                current_count = new_len;
                ++level;
                continue;
            }

            uint64_t new_len = (current_count + 1) / 2;
            std::string out_path = plot_path + ".tmp.merk" + std::to_string(level);

            stream_level(input_path, out_path, current_count, workers);

            if (input_path != leaf_path) std::remove(input_path.c_str());
            input_path = out_path;

            std::ifstream rf(out_path, std::ios::binary);
            if (rf) {
                char chunk[4 * 1024 * 1024];
                while (rf.read(chunk, sizeof(chunk)) || rf.gcount() > 0) {
                    mf.write(chunk, rf.gcount());
                }
            }

            current_count = new_len;
            ++level;
            save_checkpoint(plot_path, "MERK", total_scoops, level);
        }
        mf.close();

        std::ifstream root_f(input_path, std::ios::binary);
        if (root_f) {
            root_f.read(reinterpret_cast<char*>(root_bytes.data()), 32);
                root_hex = bytes_to_hex(root_bytes);
            std::cout << "  [MERK] root bytes: " << root_hex << std::endl;
        }
        if (root_hex.empty()) {
            root_hex = std::string(ZERO_HASH_LEN, '0');
            root_bytes = std::vector<uint8_t>(32, 0);
        }

        try { std::remove(input_path.c_str()); } catch (...) {}

        auto t2 = std::chrono::high_resolution_clock::now();
        std::cout << "  [MERK] 100% done (" << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() / 1000.0
                   << "s) root=" << bytes_to_hex(root_bytes).substr(0, 32) << "..." << std::endl;
        clear_checkpoint(plot_path);
    } else {
        if (!std::ifstream(merkle_out_path)) {
            std::cerr << "[PLOT] Merkle file missing, cannot resume WRIT" << std::endl;
            return false;
        }
        std::ifstream mf(merkle_out_path, std::ios::binary | std::ios::ate);
        if (mf) {
            auto size = mf.tellg();
            if (size >= 32) {
                mf.seekg(-32, std::ios::end);
                mf.read(reinterpret_cast<char*>(root_bytes.data()), 32);
            root_hex = bytes_to_hex(root_bytes);
            }
        }
        if (root_hex.empty()) {
            root_hex = std::string(ZERO_HASH_LEN, '0');
            root_bytes = std::vector<uint8_t>(32, 0);
        }
    }

    std::cout << "  [WRIT] Writing V3 plot file..." << std::endl;
    uint32_t id_high = (plot_id.size() >= 8) ? std::stoul(plot_id.substr(0, 8), nullptr, 16) : 0;
    uint32_t id_low = (plot_id.size() >= 16) ? std::stoul(plot_id.substr(8, 8), nullptr, 16) : 0;

    FILE* f = fopen(plot_path.c_str(), "wb");
    if (!f) {
        std::cerr << "[PLOT] Cannot open output file" << std::endl;
        return false;
    }

    std::vector<uint8_t> header(HEADER_SIZE);
    memcpy(header.data(), PLOT_MAGIC, 8);
    memcpy(header.data() + 8, uint32_to_le(PLOT_FORMAT_V3).data(), 4);
    memcpy(header.data() + 12, uint32_to_le(id_high).data(), 4);
    memcpy(header.data() + 16, uint32_to_le(id_low).data(), 4);
    {
        std::string miner_padded = miner_address;
        miner_padded.resize(44, '\0');
        memcpy(header.data() + 20, miner_padded.data(), 44);
    }
    memcpy(header.data() + 64, uint32_to_le(total_scoops).data(), 4);
    memcpy(header.data() + 68, uint32_to_le(SCOOP_SIZE).data(), 4);
    {
        std::vector<uint8_t> root_bytes(32);
        for (size_t i = 0; i < 32 && i * 2 + 1 < root_hex.size(); ++i) {
            unsigned int byte;
            sscanf(&root_hex[i * 2], "%02x", &byte);
            root_bytes[i] = static_cast<uint8_t>(byte);
        }
        memcpy(header.data() + 72, root_bytes.data(), 32);
    }
    memcpy(header.data() + 104, account.data(), 32);
    {
        auto fn_bytes = uint64_to_le(first_nonce);
        memcpy(header.data() + 136, fn_bytes.data(), 8);
    }
    fwrite(header.data(), 1, HEADER_SIZE, f);
    fflush(f);

    uint64_t num_nonces = (total_scoops + SCOOPS_PER_NONCE - 1) / SCOOPS_PER_NONCE;
    uint64_t n = 0;
    auto writ_start_time = std::chrono::high_resolution_clock::now();
    auto t1 = writ_start_time;
    uint64_t total_bytes_to_write = total_scoops * SCOOP_SIZE;
    int last_log_writ = -1;

    while (n < num_nonces) {
        uint32_t batch_nonces = static_cast<uint32_t>(std::min<uint64_t>(WRIT_BATCH_NONCES, num_nonces - n));
        uint32_t chunk_size = std::max<uint32_t>(1, (batch_nonces + workers - 1) / workers);

        std::vector<std::thread> threads;
        std::vector<std::vector<uint8_t>> results(workers);
        for (int w = 0; w < workers; ++w) {
            uint64_t start = n + w * chunk_size;
            uint64_t end = std::min(start + chunk_size, static_cast<uint64_t>(n) + batch_nonces);
            if (start >= end) break;
            threads.emplace_back([&, w, start, end]() {
                results[w] = generate_scoops_chunk(account, static_cast<uint32_t>(start), static_cast<uint32_t>(end), total_scoops, first_nonce);
            });
        }
        for (auto& t : threads) t.join();

        for (int w = 0; w < workers && w < results.size(); ++w) {
            if (!results[w].empty()) fwrite(results[w].data(), 1, results[w].size(), f);
        }

        n += batch_nonces;
        if (progress) {
            uint64_t written = n * SCOOPS_PER_NONCE;
            if (written > total_scoops) written = total_scoops;
            int pct = static_cast<int>((written * 100) / (total_scoops + 1));
            if (pct >= last_log_writ + 1) {
                last_log_writ = pct;
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::high_resolution_clock::now() - writ_start_time).count() / 1000.0;
                log_progress("WRIT", written, total_scoops, elapsed, static_cast<double>(total_bytes_to_write));
            }
        }
        save_checkpoint(plot_path, "WRIT", n * SCOOPS_PER_NONCE, 0);
    }

    std::ifstream mf_in(merkle_out_path, std::ios::binary);
    if (mf_in) {
        mf_in.seekg(0, std::ios::end);
        auto mf_size = mf_in.tellg();
        mf_in.seekg(0, std::ios::beg);
        char buf[1024 * 1024];
        while (mf_in.read(buf, sizeof(buf)) || mf_in.gcount() > 0) {
            fwrite(buf, 1, mf_in.gcount(), f);
        }
    }
    fclose(f);

    std::remove(merkle_out_path.c_str());
    clear_checkpoint(plot_path);

    auto t3 = std::chrono::high_resolution_clock::now();
    std::cout << "\n  [WRIT] 100% done (" << std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t1).count() / 1000.0 << "s)" << std::endl;

    {
        FILE* vf = fopen(plot_path.c_str(), "rb");
        if (vf) {
            fseek(vf, 0, SEEK_END);
            long fsize = ftell(vf);
            fclose(vf);
            uint64_t expected = plot_total_size(total_scoops);
            if (static_cast<uint64_t>(fsize) != expected) {
                std::cerr << "[PLOT] File size mismatch: " << fsize << " vs " << expected << std::endl;
                return false;
            }
        }
    }

    {
        FILE* vf = fopen(plot_path.c_str(), "rb");
        if (vf) {
            std::vector<uint8_t> hdr(HEADER_SIZE);
            fread(hdr.data(), 1, HEADER_SIZE, vf);
            fclose(vf);
            std::vector<uint8_t> stored_root(hdr.begin() + 72, hdr.begin() + 104);
            std::string stored_hex = bytes_to_hex(stored_root);
            if (stored_root != root_bytes) {
                std::cerr << "\n[PLOT] Root mismatch" << std::endl;
                std::cerr << "  stored: " << stored_hex.substr(0, 32) << "..." << std::endl;
                std::cerr << "  computed: " << root_hex.substr(0, 32) << "..." << std::endl;
                return false;
            }
        }
    }

    std::cout << "[PLOT] Created: " << plot_path << " (" << std::fixed << std::setprecision(3)
              << (plot_size / 1e9) << " GB, root=" << root_hex.substr(0, 32) << "...)" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: plotter <size_gb> [output_dir] [--miner <address>] [--private-key <hex>]" << std::endl;
        std::cout << "Auto-reads wallet.json if present (same dir as executable, ./wallet.json, or wallet.json)" << std::endl;
        std::cout << "Example: plotter 1 ./plots" << std::endl;
        return 1;
    }

    double size_gb = std::atof(argv[1]);
    std::string outdir = (argc >= 3) ? argv[2] : "./plots";
    std::string miner_address;
    std::vector<uint8_t> priv_key_32;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--miner" && i + 1 < argc) {
            miner_address = argv[++i];
        } else if (a == "--private-key" && i + 1 < argc) {
            std::string hex = argv[++i];
            if (hex.size() == 64) {
                priv_key_32.resize(32);
                for (int j = 0; j < 32; ++j) {
                    unsigned int byte;
                    sscanf(&hex[j * 2], "%02x", &byte);
                    priv_key_32[j] = static_cast<uint8_t>(byte);
                }
            }
        }
    }

    WalletData wallet;
    std::vector<std::string> wallet_paths = {
        std::string(argv[0]) + ".wallet.json",
        std::string("./wallet.json"),
        std::string("wallet.json"),
    };
    for (const auto& wp : wallet_paths) {
        if (load_wallet_file(wp, wallet)) {
            std::cout << "[PLOT] Loaded wallet: " << wallet.address << " from " << wp << std::endl;
            break;
        }
    }

    if (miner_address.empty()) {
        miner_address = resolve_miner_address(wallet);
    }
    if (priv_key_32.empty() && !wallet.private_key_bytes.empty()) {
        priv_key_32 = wallet.private_key_bytes;
    }

    struct stat st;
    if (stat(outdir.c_str(), &st) != 0) {
#ifdef _WIN32
        _mkdir(outdir.c_str());
#else
        mkdir(outdir.c_str(), 0755);
#endif
    }

    std::string plot_id;
    {
        std::vector<uint8_t> random_bytes(8);
        for (int i = 0; i < 8; ++i) random_bytes[i] = rand() % 256;
        plot_id = sha256_hex(random_bytes.data(), random_bytes.size()).substr(0, 16);
    }

    std::string plot_path = outdir + "/" + plot_id + ".plot";

    std::vector<uint8_t> account_id = resolve_account_id(wallet);

    bool ok = create_plot_file(plot_path, plot_id, miner_address, size_gb, account_id, true, false);

    return ok ? 0 : 1;
}
