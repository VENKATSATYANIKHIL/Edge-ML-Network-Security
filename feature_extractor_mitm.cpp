// -------------------------------------------------------------
//  Filename: arp_monitor.cpp
//  Purpose : Extract EXACT 8 features required by ML MITM model
//  ML FEATURES (in exact order):
//   1. mac_ip_inconsistency (0 or 1)
//   2. packet_in_count (int)
//   3. packet_rate (float)
//   4. rtt (avg) (float, in seconds — matches training)
//   5. is_broadcast (0 or 1)
//   6. arp_request (0 or 1)
//   7. arp_reply (0 or 1)
//   8. op_code(arp) (1=request, 2=reply)
// -------------------------------------------------------------

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <cstring>
#include <csignal>
#include <thread>
#include <mutex>
#include <iomanip>
#include <unistd.h>
#include <cstdint>

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "json.hpp"  // nlohmann JSON
using json = nlohmann::json;

// --------------------------
// CONFIG
// --------------------------
const std::string INTERFACE = "enp0s3";      // CHANGE THIS!
const int SAMPLE_WINDOW_SECONDS = 10;
const int REAPER_INTERVAL_SECONDS = 5;

// --------------------------
// ARP Packet Format
// --------------------------
struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_size;
    uint8_t  proto_size;
    uint16_t opcode;
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
} __attribute__((packed));

// --------------------------
// Per-IP statistics
// --------------------------
struct IPStats {
    std::string ip_address;

    std::map<std::string, int> mac_bindings;
    std::string dominant_mac;

    int total_packets = 0;

    // Feature 1: MAC mismatch
    int mac_mismatch_flag = 0;

    // Internal raw counts (converted to binary for ML)
    int arp_request_count = 0;
    int arp_reply_count = 0;

    // Broadcast detection
    int broadcast_count = 0;

    // RTT tracking (seconds)
    std::map<std::string, std::chrono::steady_clock::time_point> pending_requests;
    std::vector<double> rtt_samples; // store RTT in seconds

    // For opcode tracking
    int last_opcode = 1;

    std::chrono::steady_clock::time_point window_start;
    std::chrono::steady_clock::time_point last_seen;

    IPStats() {
        window_start = std::chrono::steady_clock::now();
        last_seen = window_start;
    }

    // -------------------------------
    // MAC binding logic (binary mismatch)
    // -------------------------------
    void update_mac_binding(const std::string &mac) {
        mac_bindings[mac]++;

        std::string best_mac;
        int best_count = 0;

        for (auto &p : mac_bindings) {
            if (p.second > best_count) {
                best_count = p.second;
                best_mac = p.first;
            }
        }

        // If dominant_mac already set and a different mac observed -> mark mismatch
        if (!dominant_mac.empty() && mac != dominant_mac) {
            mac_mismatch_flag = 1;
        }

        dominant_mac = best_mac;
    }

    // -------------------------------
    // Output EXACT 8 ML features
    // -------------------------------
    void print_features_json() const {
        auto now = std::chrono::steady_clock::now();
        double duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now - window_start).count() / 1000.0; // seconds

        // Feature 1
        int mac_ip_inconsistency = mac_mismatch_flag;

        // Feature 2
        int packet_in_count = total_packets;

        // Feature 3
        double packet_rate = (duration > 0.0 ? packet_in_count / duration : 0.0);

        // Feature 4 (RTT in seconds to match training)
        double rtt_avg = 0.0;
        if (!rtt_samples.empty()) {
            double sum = 0.0;
            for (double r : rtt_samples) sum += r;
            rtt_avg = sum / rtt_samples.size(); // seconds
        }

        // Feature 5
        int is_broadcast_flag = (broadcast_count > 0 ? 1 : 0);

        // Feature 6 (binary only)
        int arp_request_flag = (arp_request_count > 0 ? 1 : 0);

        // Feature 7 (binary only)
        int arp_reply_flag = (arp_reply_count > 0 ? 1 : 0);

        // Feature 8
        int op_code_arp = last_opcode;

        json out;
        out["feature_type"] = "mitm";
        out["ip_address"] = ip_address;

        // EXACT order as ML model expects
        out["features"] = {
            mac_ip_inconsistency,
            packet_in_count,
            packet_rate,
            rtt_avg,
            is_broadcast_flag,
            arp_request_flag,
            arp_reply_flag,
            op_code_arp
        };

        std::cout << out.dump() << std::endl;
    }

    // Reset window
    void reset() {
        std::string ip = ip_address;
        *this = IPStats();
        ip_address = ip;
    }
};

// --------------------------
// GLOBALS
// --------------------------
std::map<std::string, IPStats> ip_statistics;
std::mutex stats_mutex;
bool stop_capture = false;
pcap_t *handle = nullptr;

// --------------------------
// Utility
// --------------------------
std::string mac_to_string(const uint8_t *mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

std::string ip_to_string(const uint8_t *ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

bool is_broadcast_mac(const uint8_t *mac) {
    static const uint8_t bc[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    return std::memcmp(mac, bc, 6) == 0;
}

// --------------------------
// ARP packet handler
// --------------------------
void process_arp_packet(u_char *, const struct pcap_pkthdr *header, const u_char *packet) {
    // ensure packet is long enough
    size_t min_len = sizeof(struct ether_header) + sizeof(struct arp_header);
    if (header->caplen < min_len) return;

    if (ntohs(((struct ether_header*)packet)->ether_type) != ETHERTYPE_ARP)
        return;

    auto now = std::chrono::steady_clock::now();
    auto *arp = (struct arp_header*)(packet + sizeof(struct ether_header));

    uint16_t opcode = ntohs(arp->opcode);
    std::string sender_ip = ip_to_string(arp->sender_ip);
    std::string sender_mac = mac_to_string(arp->sender_mac);
    std::string target_ip = ip_to_string(arp->target_ip);

    std::lock_guard<std::mutex> lock(stats_mutex);

    // create or get stats for sender_ip
    auto it = ip_statistics.find(sender_ip);
    if (it == ip_statistics.end()) {
        // insert and ensure window_start is set to 'now'
        IPStats s;
        s.ip_address = sender_ip;
        s.window_start = now;
        s.last_seen = now;
        auto res = ip_statistics.emplace(sender_ip, std::move(s));
        it = res.first;
    }

    IPStats &stats = it->second;

    stats.total_packets++;
    stats.last_seen = now;
    stats.last_opcode = static_cast<int>(opcode);

    stats.update_mac_binding(sender_mac);

    if (opcode == 1) {
        stats.arp_request_count++;
        stats.pending_requests[target_ip] = now;
    } else if (opcode == 2) {
        stats.arp_reply_count++;

        // compute RTT in seconds if matching pending request found
        if (ip_statistics.count(target_ip)) {
            auto &req_stats = ip_statistics[target_ip];
            auto req_it = req_stats.pending_requests.find(sender_ip);
            if (req_it != req_stats.pending_requests.end()) {
                double rtt_seconds = std::chrono::duration_cast<std::chrono::microseconds>(
                                        now - req_it->second).count() / 1e6; // seconds
                req_stats.rtt_samples.push_back(rtt_seconds);
                req_stats.pending_requests.erase(req_it);
            }
        }
    }

    // detect broadcast on ethernet destination
    if (is_broadcast_mac(((struct ether_header*)packet)->ether_dhost))
        stats.broadcast_count++;
}

// --------------------------
// Reaper thread
// --------------------------
void sample_and_expire() {
    while (!stop_capture) {
        std::this_thread::sleep_for(std::chrono::seconds(REAPER_INTERVAL_SECONDS));

        auto now = std::chrono::steady_clock::now();
        std::vector<std::string> to_remove;

        std::lock_guard<std::mutex> lock(stats_mutex);

        for (auto &p : ip_statistics) {
            auto &stats = p.second;

            double window_time = std::chrono::duration_cast<std::chrono::seconds>(
                                     now - stats.window_start).count();
            double idle_time = std::chrono::duration_cast<std::chrono::seconds>(
                                   now - stats.last_seen).count();

            if (window_time >= SAMPLE_WINDOW_SECONDS || idle_time >= SAMPLE_WINDOW_SECONDS) {

                if (stats.total_packets > 0)
                    stats.print_features_json();

                if (idle_time >= SAMPLE_WINDOW_SECONDS)
                    to_remove.push_back(p.first);
                else
                    stats.reset();
            }
        }

        for (auto &ip : to_remove)
            ip_statistics.erase(ip);
    }
}

// --------------------------
// MAIN
// --------------------------
void signal_handler(int) {
    stop_capture = true;
    if (handle) pcap_breakloop(handle);
}

int main() {
    if (geteuid() != 0) {
        std::cerr << "[-] Run as root.\n";
        return 1;
    }

    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(INTERFACE.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "[-] Could not open device " << INTERFACE << "\n";
        return 2;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "[-] Could not apply ARP filter.\n";
        pcap_close(handle);
        return 3;
    }

    std::thread sampler(sample_and_expire);

    std::cerr << "[*] ARP MITM Monitor active on " << INTERFACE << "\n";
    pcap_loop(handle, -1, process_arp_packet, nullptr);

    pcap_freecode(&fp);
    pcap_close(handle);
    sampler.join();

    std::cerr << "[+] Shutdown.\n";
    return 0;
}
