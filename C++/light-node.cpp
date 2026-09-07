#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include <atomic>
#include <cstdio>
#include <iomanip>
#include <curl/curl.h>
#include <sqlite3.h>
#include <json-c/json.h>

class LightNode {
private:
    std::atomic<bool> running;
    std::atomic<int> currentBlockHeight;
    std::vector<std::string> node_urls;
    const int sliding_window = 8192;
    int server_fd;
    std::string db_path;

    struct BlockHeader {
        int height;
        std::string hash;
        std::string parent_hash;
        std::string state_root;
        std::string tx_root;
        std::string timestamp;
        std::string miner;
        int poh_sequence_count;
        int gas_used;
        int gas_limit;
        int tx_count;
        double size_kb;
    };

    static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    std::string fetch_url(const std::string& url) {
        CURL* curl = curl_easy_init();
        std::string response;
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "[HTTP] error: " << curl_easy_strerror(res) << std::endl;
            }
            curl_easy_cleanup(curl);
        }
        return response;
    }

    bool parse_json_blocks(const std::string& json_str, std::vector<BlockHeader>& blocks) {
        json_object* jobj = json_tokener_parse(json_str.c_str());
        if (!jobj) return false;

        json_object* jblocks;
        if (!json_object_object_get_ex(jobj, "blocks", &jblocks)) {
            json_object_put(jobj);
            return false;
        }

        int count = json_object_array_length(jblocks);

        blocks.clear();
        for (int i = 0; i < count && i < 200; i++) {
            json_object* jblock = json_object_array_get_idx(jblocks, i);
            if (!jblock) continue;

            BlockHeader bh;

            json_object* jh = nullptr;
            if (json_object_object_get_ex(jblock, "height", &jh) && jh) {
                bh.height = json_object_get_int(jh);
            }

            json_object* jhash = nullptr;
            if (json_object_object_get_ex(jblock, "hash", &jhash) && jhash) {
                bh.hash = json_object_get_string(jhash);
            }

            json_object* jparent = nullptr;
            if (json_object_object_get_ex(jblock, "parent_hash", &jparent) && jparent) {
                bh.parent_hash = json_object_get_string(jparent);
            }

            json_object* jstate = nullptr;
            if (json_object_object_get_ex(jblock, "state_root", &jstate) && jstate) {
                bh.state_root = json_object_get_string(jstate);
            }

            json_object* jtx = nullptr;
            if (json_object_object_get_ex(jblock, "tx_root", &jtx) && jtx) {
                bh.tx_root = json_object_get_string(jtx);
            }

            json_object* jts = nullptr;
            if (json_object_object_get_ex(jblock, "timestamp", &jts) && jts) {
                bh.timestamp = json_object_get_string(jts);
            }

            json_object* jminer = nullptr;
            if (json_object_object_get_ex(jblock, "miner", &jminer) && jminer) {
                bh.miner = json_object_get_string(jminer);
            }

            json_object* jpoh = nullptr;
            if (json_object_object_get_ex(jblock, "poh_sequence_count", &jpoh) && jpoh) {
                bh.poh_sequence_count = json_object_get_int(jpoh);
            }

            json_object* jgas_used = nullptr;
            if (json_object_object_get_ex(jblock, "gas_used", &jgas_used) && jgas_used) {
                bh.gas_used = json_object_get_int(jgas_used);
            }

            json_object* jgas_limit = nullptr;
            if (json_object_object_get_ex(jblock, "gas_limit", &jgas_limit) && jgas_limit) {
                bh.gas_limit = json_object_get_int(jgas_limit);
            }

            json_object* jtx_count = nullptr;
            if (json_object_object_get_ex(jblock, "tx_count", &jtx_count) && jtx_count) {
                bh.tx_count = json_object_get_int(jtx_count);
            }

            const char* block_json = json_object_to_json_string(jblock);
            if (block_json) {
                bh.size_kb = strlen(block_json) / 1024.0;
            }

            blocks.push_back(bh);
        }

        json_object_put(jobj);
        return !blocks.empty();
    }

    int execute_sql(sqlite3* db, const std::string& sql) {
        char* errmsg = nullptr;
        int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::cerr << "[SQL] error: " << (errmsg ? errmsg : "unknown") << std::endl;
            sqlite3_free(errmsg);
        }
        return rc;
    }

public:
    LightNode()
        : running(true), currentBlockHeight(0), node_urls{"https://seed1.chocohub.org", "https://seed2.chocohub.org"}, server_fd(-1), db_path("blockchain/blocks.db") {}

    ~LightNode() {
        stop();
    }

    void set_db_path(const std::string& path) { db_path = path; }

    void start() {
        std::cout << "[HELPER] Starting Light Node..." << std::endl;
        running.store(true);
        std::thread tcpThread(&LightNode::startTcpServer, this);
        tcpThread.detach();

        while (running.load()) {
            syncBlocks();
            std::this_thread::sleep_for(std::chrono::seconds(3));
        }
    }

    void startTcpServer() {
        const int PORT = 3001;
        struct sockaddr_in address;
        int opt = 1;
        socklen_t addrlen = sizeof(address);

        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            perror("[TCP] socket failed");
            return;
        }

        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            perror("[TCP] setsockopt SO_REUSEADDR failed");
        }
#ifdef SO_REUSEPORT
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
            perror("[TCP] setsockopt SO_REUSEPORT failed");
        }
#endif

        std::memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(PORT);

        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            perror("[TCP] bind failed");
            close(server_fd);
            server_fd = -1;
            return;
        }

        if (listen(server_fd, 3) < 0) {
            perror("[TCP] listen failed");
            close(server_fd);
            server_fd = -1;
            return;
        }

        std::cout << "[TCP] Listening on port " << PORT << "..." << std::endl;

        while (running.load()) {
            int new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen);
            if (new_socket < 0) {
                if (!running.load()) break;
                perror("[TCP] accept failed");
                continue;
            }

            char buffer[1024] = {0};
            ssize_t valread = read(new_socket, buffer, sizeof(buffer) - 1);
            if (valread > 0) buffer[valread] = '\0';
            else buffer[0] = '\0';
            std::cout << "[TCP] Received: " << buffer << std::endl;

            std::string response = "{\"status\":\"success\",\"current_block\":" + std::to_string(currentBlockHeight.load()) + "}\n";
            ssize_t written = write(new_socket, response.c_str(), response.length());
            if (written < 0) perror("[TCP] write failed");

            close(new_socket);
        }

        if (server_fd >= 0) {
            close(server_fd);
            server_fd = -1;
        }
    }

    void syncBlocks() {
        std::cout << "[LightNode] Syncing Block..." << std::endl;

        mkdir("blocks_sync", 0755);

        sqlite3* db;
        int rc = sqlite3_open(db_path.c_str(), &db);
        if (rc != SQLITE_OK) {
            std::cerr << "[SQL] can't open database: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return;
        }

        execute_sql(db,
            "CREATE TABLE IF NOT EXISTS blocks("
            "height INTEGER PRIMARY KEY,"
            "hash TEXT NOT NULL,"
            "parent_hash TEXT NOT NULL,"
            "state_root TEXT,"
            "tx_root TEXT,"
            "timestamp TEXT)");
        execute_sql(db, "CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash)");

        std::string first_url = node_urls[0];
        std::string node_info = fetch_url(first_url + "/api/node/info");

        int tip_height = 0;
        json_object* jinfo = json_tokener_parse(node_info.c_str());
        if (jinfo) {
            json_object* jheight;
            if (json_object_object_get_ex(jinfo, "height", &jheight) && jheight) {
                tip_height = json_object_get_int(jheight);
            }
            json_object_put(jinfo);
        }

        int last_height = -1;
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT MAX(height) FROM blocks", -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                last_height = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        int from_height = last_height + 1;
        if (from_height > tip_height) {
            sqlite3_close(db);
            int newHeight = currentBlockHeight.load();
            std::cout << "[LightNode] already synced to tip " << newHeight << std::endl;
            return;
        }

        std::vector<BlockHeader> blocks;
        int h = from_height;
        while (h <= tip_height) {
            int limit = std::min(200, tip_height - h + 1);
            std::string url = first_url + "/api/blocks?from=" + std::to_string(h) + "&limit=" + std::to_string(limit);
            std::string resp = fetch_url(url);

            std::vector<BlockHeader> batch;
            if (!parse_json_blocks(resp, batch) || batch.empty()) {
                break;
            }

            for (const auto& bh : batch) {
                std::string sql = "INSERT OR REPLACE INTO blocks(height,hash,parent_hash,state_root,tx_root,timestamp) VALUES("
                    + std::to_string(bh.height) + ",'"
                    + bh.hash + "','"
                    + bh.parent_hash + "','"
                    + bh.state_root + "','"
                    + bh.tx_root + "','"
                    + bh.timestamp + "')";
                execute_sql(db, sql);

                 std::cout << "[LightNode] downloaded block #" << bh.height
                           << " hash=" << bh.hash.substr(0,20) << " parent=" << bh.parent_hash.substr(0,20)
                           << " miner=" << (bh.miner.empty() ? "unknown" : bh.miner.substr(0,20))
                           << " TX: tx_count=" << bh.tx_count
                           << " Gas: " << bh.gas_used << "/" << bh.gas_limit
                           << " Size: " << std::fixed << std::setprecision(2) << bh.size_kb << " KB"
                           << " poh=" << bh.poh_sequence_count
                           << std::endl;
            }

            blocks.insert(blocks.end(), batch.begin(), batch.end());
            h += batch.size();
            if (batch.size() < limit) break;
        }

        if (!blocks.empty()) {
            currentBlockHeight.store(blocks.back().height);
        } else if (tip_height > currentBlockHeight.load()) {
            currentBlockHeight.store(tip_height);
        }

        sqlite3_close(db);

        int newHeight = currentBlockHeight.load();
        std::cout << "[LightNode] Synced to block " << newHeight << std::endl;
    }

    void stop() {
        bool expected = true;
        if (running.compare_exchange_strong(expected, false)) {
            std::cout << "[LightNode] Gracefully Shutting Down" << std::endl;
            if (server_fd >= 0) {
                close(server_fd);
                server_fd = -1;
            }
        }
    }
};

int main() {
    LightNode node;
    node.start();

    std::cout << "[HELPER] Stopping Node... :(" << std::endl;
    return 0;
}
