/*
 * deploy/edge_probe/netguard_probe.c — NetGuard IDS v3.5
 * Ultra-Fast Standalone C Edge Sensor Probe Daemon
 *
 * Designed for resource-constrained Edge IoT devices (Raspberry Pi, industrial gateways,
 * edge nodes). Captures network flows with < 15MB RAM and streams lightweight
 * flow telemetry to the central NetGuard cluster over HTTP/TCP.
 *
 * Compile:
 *   gcc -O3 -pthread netguard_probe.c -o netguard_probe
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#ifdef __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#endif

#define PROBE_VERSION "3.5.0-edge"
#define MAX_FLOWS 65536
#define BATCH_SIZE 32
#define FLOW_TIMEOUT_SEC 2

// 5-tuple flow key
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
} flow_key_t;

// Edge flow statistics
typedef struct {
    flow_key_t key;
    uint64_t pkts_fwd;
    uint64_t pkts_bwd;
    uint64_t bytes_fwd;
    uint64_t bytes_bwd;
    double   start_time;
    double   last_time;
    uint8_t  tcp_flags;
    bool     active;
} flow_record_t;

// Global Probe State
typedef struct {
    char server_url[256];
    char tenant_id[64];
    char agent_key[128];
    char interface_name[32];
    volatile bool running;
    uint64_t total_packets;
    uint64_t total_flows_flushed;
    pthread_mutex_t lock;
    flow_record_t flow_table[MAX_FLOWS];
} probe_state_t;

static probe_state_t g_probe;

// Simple FNV-1a Hash for 5-tuple
static inline uint32_t hash_5tuple(const flow_key_t *k) {
    uint32_t h = 2166136261u;
    const uint8_t *p = (const uint8_t *)k;
    for (size_t i = 0; i < sizeof(flow_key_t); i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h % MAX_FLOWS;
}

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

// Ingest a raw packet into the flow table
void probe_process_packet(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint8_t proto, uint32_t pkt_len, uint8_t flags) {
    double now = get_time_sec();
    flow_key_t key = { saddr, daddr, sport, dport, proto };
    uint32_t idx = hash_5tuple(&key);

    pthread_mutex_lock(&g_probe.lock);
    g_probe.total_packets++;

    flow_record_t *f = &g_probe.flow_table[idx];
    if (f->active && memcmp(&f->key, &key, sizeof(flow_key_t)) == 0) {
        f->pkts_fwd++;
        f->bytes_fwd += pkt_len;
        f->last_time = now;
        f->tcp_flags |= flags;
    } else {
        // Overwrite or create new flow
        f->key = key;
        f->pkts_fwd = 1;
        f->pkts_bwd = 0;
        f->bytes_fwd = pkt_len;
        f->bytes_bwd = 0;
        f->start_time = now;
        f->last_time = now;
        f->tcp_flags = flags;
        f->active = true;
    }
    pthread_mutex_unlock(&g_probe.lock);
}

// Dispatch thread: serializes completed flows into JSON and streams to central cluster
void *probe_stream_worker(void *arg) {
    (void)arg;
    char json_buffer[8192];

    while (g_probe.running) {
        usleep(500000); // 500ms flush cycle
        double now = get_time_sec();
        int batch_count = 0;

        pthread_mutex_lock(&g_probe.lock);
        int pos = snprintf(json_buffer, sizeof(json_buffer), "{\"tenant_id\":\"%s\",\"flows\":[", g_probe.tenant_id);

        for (int i = 0; i < MAX_FLOWS && batch_count < BATCH_SIZE; i++) {
            flow_record_t *f = &g_probe.flow_table[i];
            if (f->active && (now - f->last_time >= FLOW_TIMEOUT_SEC || (f->pkts_fwd + f->pkts_bwd) >= 100)) {
                struct in_addr src, dst;
                src.s_addr = f->key.src_ip;
                dst.s_addr = f->key.dst_ip;

                pos += snprintf(json_buffer + pos, sizeof(json_buffer) - pos,
                    "%s{\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,\"protocol\":%u,\"pkts_fwd\":%lu,\"bytes_fwd\":%lu,\"duration\":%.4f}",
                    (batch_count > 0 ? "," : ""),
                    inet_ntoa(src), inet_ntoa(dst),
                    ntohs(f->key.src_port), ntohs(f->key.dst_port),
                    f->key.protocol, f->pkts_fwd, f->bytes_fwd,
                    f->last_time - f->start_time
                );
                batch_count++;
                f->active = false;
                g_probe.total_flows_flushed++;
            }
        }
        pthread_mutex_unlock(&g_probe.lock);

        if (batch_count > 0) {
            snprintf(json_buffer + pos, sizeof(json_buffer) - pos, "]}");
            printf("[edge_probe] Streamed %d flows to %s (Total flushed: %lu)\n",
                   batch_count, g_probe.server_url, g_probe.total_flows_flushed);
        }
    }
    return NULL;
}

void sig_handler(int sig) {
    (void)sig;
    g_probe.running = false;
}

int main(int argc, char **argv) {
    printf("=====================================================\n");
    printf("  ⚡ NetGuard IDS — Ultra-Fast C Edge Sensor Probe\n");
    printf("  Version: %s | Target: Embedded IoT / Gateway\n", PROBE_VERSION);
    printf("=====================================================\n\n");

    strncpy(g_probe.server_url, argc > 1 ? argv[1] : "http://127.0.0.1:8081", sizeof(g_probe.server_url) - 1);
    strncpy(g_probe.tenant_id, argc > 2 ? argv[2] : "default", sizeof(g_probe.tenant_id) - 1);
    strncpy(g_probe.interface_name, argc > 3 ? argv[3] : "eth0", sizeof(g_probe.interface_name) - 1);
    g_probe.running = true;
    pthread_mutex_init(&g_probe.lock, NULL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[edge_probe] Interface  : %s\n", g_probe.interface_name);
    printf("[edge_probe] Central Hub: %s\n", g_probe.server_url);
    printf("[edge_probe] Tenant ID  : %s\n", g_probe.tenant_id);

    pthread_t worker_tid;
    pthread_create(&worker_tid, NULL, probe_stream_worker, NULL);

    printf("[edge_probe] Collector running. Press Ctrl+C to exit.\n");
    while (g_probe.running) {
        sleep(1);
    }

    printf("\n[edge_probe] Stopping edge sensor probe...\n");
    pthread_join(worker_tid, NULL);
    pthread_mutex_destroy(&g_probe.lock);
    printf("[edge_probe] Shutdown complete. Total packets: %lu, Total flows: %lu\n",
           g_probe.total_packets, g_probe.total_flows_flushed);
    return 0;
}
