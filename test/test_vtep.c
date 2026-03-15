
/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : test_vtep.c  
 * Purpose     : VXLAN VTEP demo
 *****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include "../include/vxlan.h"

static volatile int keep_running = 1;

void signal_handler(int signum) {
    (void)signum;
    keep_running = 0;
    printf("\nShutting down...\n");
}

void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -i <ip>      Local VTEP IP address (default: 192.168.1.100)\n");
    printf("  -v <vni>     VXLAN Network Identifier (default: 100)\n");
    printf("  -p <port>    UDP port (default: 4789)\n");
    printf("  -m <ip>      Multicast group IP for BUM traffic\n");
    printf("  -h           Show this help\n");
}

int main(int argc, char *argv[]) {
    vxlan_ctx_t ctx;
    uint32_t local_ip = inet_addr("192.168.1.100");
    uint32_t vni = 100;
    uint16_t udp_port = VXLAN_UDP_PORT;
    uint32_t mcast_ip = 0;
    
    /* Parse command line arguments */
    int opt;
    while ((opt = getopt(argc, argv, "i:v:p:m:h")) != -1) {
        switch (opt) {
            case 'i':
                local_ip = inet_addr(optarg);
                break;
            case 'v':
                vni = atoi(optarg);
                break;
            case 'p':
                udp_port = atoi(optarg);
                break;
            case 'm':
                mcast_ip = inet_addr(optarg);
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }
    
    /* Initialize VXLAN */
    printf("Initializing VXLAN VTEP...\n");
    if (vxlan_init(&ctx, local_ip, vni) != 0) {
        fprintf(stderr, "Failed to initialize VXLAN\n");
        return 1;
    }
    
    /* Configure optional settings */
    if (udp_port != VXLAN_UDP_PORT) {
        vxlan_set_udp_port(&ctx, udp_port);
    }
    
    if (mcast_ip != 0) {
        vxlan_set_multicast_group(&ctx, mcast_ip);
    }
    
    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("\n===========================================\n");
    printf("VXLAN VTEP Example - Encapsulation Demo\n");
    printf("===========================================\n\n");
    
    /* ============ EXAMPLE 1: Basic Encapsulation ============ */
    printf("Example 1: Basic Frame Encapsulation\n");
    printf("--------------------------------------\n");
    
    /* Create a simple inner Ethernet frame */
    uint8_t inner_frame[128];
    eth_hdr_t *inner_eth = (eth_hdr_t *)inner_frame;
    
    /* Destination MAC: aa:bb:cc:dd:ee:ff */
    uint8_t dst_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    /* Source MAC: 11:22:33:44:55:66 */
    uint8_t src_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    
    memcpy(inner_eth->dst_mac, dst_mac, 6);
    memcpy(inner_eth->src_mac, src_mac, 6);
    inner_eth->ether_type = htons(0x0800); /* IPv4 */
    
    /* Add some payload */
    const char *payload = "Hello VXLAN!";
    memcpy(inner_frame + sizeof(eth_hdr_t), payload, strlen(payload));
    size_t inner_len = sizeof(eth_hdr_t) + strlen(payload);
    
    printf("Inner frame: %zu bytes\n", inner_len);
    printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    printf("  Payload: \"%s\"\n", payload);
    
    /* Encapsulate */
    uint8_t outer_packet[2048];
    size_t outer_len;
    uint32_t remote_vtep = inet_addr("192.168.1.200");
    
    printf("\nEncapsulating to remote VTEP: %s\n", inet_ntoa(*(struct in_addr*)&remote_vtep));
    
    if (vxlan_encapsulate(&ctx, inner_frame, inner_len, 
                          outer_packet, &outer_len, remote_vtep) != 0) {
        fprintf(stderr, "Encapsulation failed\n");
    } else {
        printf("Encapsulated packet: %zu bytes (overhead: %zu bytes)\n", 
               outer_len, outer_len - inner_len);
        
        /* Dump the encapsulated packet */
        vxlan_dump_packet(outer_packet, outer_len, "Encapsulated Packet");
    }
    
    /* ============ EXAMPLE 2: Decapsulation ============ */
    printf("\n\nExample 2: Packet Decapsulation\n");
    printf("--------------------------------\n");
    
    /* Decapsulate the packet we just created */
    uint8_t decap_frame[2048];
    size_t decap_len;
    uint32_t src_vtep;
    uint32_t rx_vni;
    
    if (vxlan_decapsulate(&ctx, outer_packet, outer_len,
                          decap_frame, &decap_len,
                          &src_vtep, &rx_vni) != 0) {
        fprintf(stderr, "Decapsulation failed\n");
    } else {
        printf("Decapsulated successfully!\n");
        printf("  Source VTEP: %s\n", inet_ntoa(*(struct in_addr*)&src_vtep));
        printf("  VNI: %u\n", rx_vni);
        printf("  Inner frame: %zu bytes\n", decap_len);
        
        /* Verify the payload */
        eth_hdr_t *decap_eth = (eth_hdr_t *)decap_frame;
        char *decap_payload = (char *)(decap_frame + sizeof(eth_hdr_t));
        
        printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               decap_eth->src_mac[0], decap_eth->src_mac[1],
               decap_eth->src_mac[2], decap_eth->src_mac[3],
               decap_eth->src_mac[4], decap_eth->src_mac[5]);
        printf("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               decap_eth->dst_mac[0], decap_eth->dst_mac[1],
               decap_eth->dst_mac[2], decap_eth->dst_mac[3],
               decap_eth->dst_mac[4], decap_eth->dst_mac[5]);
        printf("  Payload: \"%.*s\"\n", 
               (int)(decap_len - sizeof(eth_hdr_t)), decap_payload);
        
        /* Verify integrity */
        if (memcmp(inner_frame, decap_frame, inner_len) == 0) {
            printf("\n✓ Frame integrity verified!\n");
        } else {
            printf("\n✗ Frame mismatch!\n");
        }
    }
    
    /* ============ EXAMPLE 3: MAC Learning ============ */
    printf("\n\nExample 3: MAC Address Learning\n");
    printf("--------------------------------\n");
    
    /* The decapsulation automatically learned the MAC */
    printf("\nMAC Learning Table after decapsulation:\n");
    vxlan_mac_dump(&ctx);
    
    /* Test MAC lookup */
    uint32_t learned_vtep;
    if (vxlan_mac_lookup(&ctx, src_mac, vni, &learned_vtep) == 0) {
        printf("MAC lookup successful:\n");
        printf("  MAC %02x:%02x:%02x:%02x:%02x:%02x is at VTEP %s\n",
               src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
               inet_ntoa(*(struct in_addr*)&learned_vtep));
    }
    
    /* ============ EXAMPLE 4: Multiple VNI Support ============ */
    printf("\n\nExample 4: Multiple VNI Support\n");
    printf("--------------------------------\n");
    
    /* Learn MACs from different VNIs */
    uint8_t mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t mac2[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x66};
    uint32_t vtep1 = inet_addr("192.168.1.201");
    uint32_t vtep2 = inet_addr("192.168.1.202");
    
    vxlan_mac_learn(&ctx, mac1, vtep1, 100);  /* VNI 100 */
    vxlan_mac_learn(&ctx, mac2, vtep2, 200);  /* VNI 200 */
    vxlan_mac_learn(&ctx, mac1, vtep2, 200);  /* Same MAC, different VNI */
    
    printf("\nMAC Table with multiple VNIs:\n");
    vxlan_mac_dump(&ctx);
    
    /* ============ EXAMPLE 5: Statistics ============ */
    printf("\n\nExample 5: Statistics\n");
    printf("---------------------\n");
    
    vxlan_stats_t stats;
    vxlan_get_stats(&ctx, &stats);
    
    printf("VXLAN Statistics:\n");
    printf("  MAC Table Entries: %lu\n", stats.mac_learning_count);
    printf("  TX Packets: %lu\n", stats.tx_packets);
    printf("  RX Packets: %lu\n", stats.rx_packets);
    printf("  TX Bytes: %lu\n", stats.tx_bytes);
    printf("  RX Bytes: %lu\n", stats.rx_bytes);
    
    /* ============ EXAMPLE 6: Aging Simulation ============ */
    printf("\n\nExample 6: MAC Aging Simulation\n");
    printf("--------------------------------\n");
    
    printf("Waiting 2 seconds before aging check...\n");
    sleep(2);
    
    int aged = vxlan_mac_age(&ctx);
    printf("Aged out %d entries (aging timeout: %d seconds)\n", 
           aged, MAC_AGING_TIME);
    
    /* ============ Cleanup ============ */
    printf("\n\nCleaning up...\n");
    vxlan_cleanup(&ctx);
    
    printf("\n===========================================\n");
    printf("VXLAN VTEP Example Completed Successfully!\n");
    printf("===========================================\n\n");
    
    return 0;
}
