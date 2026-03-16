
/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : vxlan.h  
 * Purpose     : Main header file containing protocol definitions and API
 *****************************************************************************/


#ifndef VXLAN_H
#define VXLAN_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

/* VLAN tag handling */
#include "vxlan_vlan.h"

/* ==================== Protocol Constants ==================== */

#define VXLAN_UDP_PORT          4789    /* IANA assigned port */
#define VXLAN_HEADER_SIZE       8       /* VXLAN header is 8 bytes */
#define VXLAN_I_FLAG            0x08    /* Bit 4 (I flag) must be 1 */

#define VXLAN_VNI_MAX           0xFFFFFF /* 24-bit VNI (16,777,215) */
#define VXLAN_SRC_PORT_MIN      49152    /* Dynamic port range start */
#define VXLAN_SRC_PORT_MAX      65535    /* Dynamic port range end */

#define VXLAN_MTU_OVERHEAD      50      /* Approx overhead: 8(VXLAN) + 8(UDP) + 20(IP) + 14(Eth) */

/* MAC Learning Table */
#define MAC_TABLE_SIZE          1024
#define MAC_AGING_TIME          300     /* seconds */

/* ==================== Data Structures ==================== */

/**
 * VXLAN Header Structure (8 bytes)
 * 
 * Bit Layout (RFC 7348):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |R|R|R|R|I|R|R|R|            Reserved                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        VXLAN Network Identifier (VNI)         |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct {
    uint8_t  flags;         /* Flags byte (I flag at bit 4) */
    uint8_t  reserved1[3];  /* Reserved - must be 0 */
    uint8_t  vni[3];        /* 24-bit VNI (network byte order) */
    uint8_t  reserved2;     /* Reserved - must be 0 */
} __attribute__((packed)) vxlan_hdr_t;

/**
 * Ethernet Frame Header
 */
typedef struct {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;
} __attribute__((packed)) eth_hdr_t;

/**
 * IPv4 Header (simplified)
 */
typedef struct {
    uint8_t  ver_ihl;       /* Version (4 bits) + IHL (4 bits) */
    uint8_t  tos;           /* Type of Service */
    uint16_t total_len;     /* Total Length */
    uint16_t id;            /* Identification */
    uint16_t frag_off;      /* Flags (3 bits) + Fragment Offset (13 bits) */
    uint8_t  ttl;           /* Time to Live */
    uint8_t  protocol;      /* Protocol (17 for UDP) */
    uint16_t checksum;      /* Header Checksum */
    uint32_t src_ip;        /* Source IP Address */
    uint32_t dst_ip;        /* Destination IP Address */
} __attribute__((packed)) ip_hdr_t;

/**
 * UDP Header
 */
typedef struct {
    uint16_t src_port;      /* Source Port */
    uint16_t dst_port;      /* Destination Port */
    uint16_t length;        /* UDP Length */
    uint16_t checksum;      /* Checksum (0 or computed) */
} __attribute__((packed)) udp_hdr_t;

/**
 * Complete VXLAN Packet (inner frame + encapsulation)
 */
typedef struct {
    eth_hdr_t   outer_eth;
    ip_hdr_t    outer_ip;
    udp_hdr_t   outer_udp;
    vxlan_hdr_t vxlan;
    eth_hdr_t   inner_eth;
    uint8_t     payload[ETH_DATA_LEN]; /* Max Ethernet payload */
} __attribute__((packed)) vxlan_packet_t;

/**
 * VTEP (VXLAN Tunnel End Point) Configuration
 */
typedef struct {
    uint32_t    local_ip;       /* Local VTEP IP address */
    uint8_t     local_mac[6];   /* Local MAC address */
    uint32_t    vni;            /* VXLAN Network Identifier */
    uint32_t    multicast_ip;   /* Multicast group IP (for BUM traffic) */
    uint16_t    udp_port;       /* UDP destination port (default 4789) */
    int         sockfd;         /* Socket file descriptor */
    bool        checksum_enabled; /* Enable UDP checksum calculation */
} vtep_t;

/**
 * MAC Learning Table Entry
 */
typedef struct mac_entry {
    uint8_t     mac[6];         /* MAC address */
    uint32_t    vtep_ip;        /* Remote VTEP IP */
    uint32_t    vni;            /* VNI */
    time_t      timestamp;      /* Last seen time */
    struct mac_entry *next;     /* Hash table chaining */
} mac_entry_t;

/**
 * VXLAN Context (global state)
 */
typedef struct {
    vtep_t        vtep;             /* VTEP configuration */
    mac_entry_t  *mac_table[MAC_TABLE_SIZE]; /* MAC learning table */
    pthread_mutex_t mac_lock;       /* Thread safety for MAC table */
    bool          running;          /* Service running flag */
    vlan_config_t vlan_config;      /* VLAN tag handling configuration */
} vxlan_ctx_t;

/**
 * Statistics
 */
typedef struct {
    uint64_t tx_packets;
    uint64_t rx_packets;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t encap_errors;
    uint64_t decap_errors;
    uint64_t mac_learning_count;
} vxlan_stats_t;

/* ==================== API Functions ==================== */

/**
 * Initialize VXLAN context
 * 
 * @param ctx       Pointer to VXLAN context
 * @param local_ip  Local VTEP IP address (network byte order)
 * @param vni       VXLAN Network Identifier (24-bit)
 * @return          0 on success, -1 on error
 */
int vxlan_init(vxlan_ctx_t *ctx, uint32_t local_ip, uint32_t vni);

/**
 * Cleanup VXLAN context
 * 
 * @param ctx   Pointer to VXLAN context
 */
void vxlan_cleanup(vxlan_ctx_t *ctx);

/**
 * Encapsulate an Ethernet frame in VXLAN
 * 
 * @param ctx           VXLAN context
 * @param inner_frame   Inner Ethernet frame
 * @param inner_len     Length of inner frame
 * @param outer_packet  Output buffer for encapsulated packet
 * @param outer_len     Output length of encapsulated packet
 * @param dst_vtep_ip   Destination VTEP IP (network byte order)
 * @return              0 on success, -1 on error
 */
int vxlan_encapsulate(vxlan_ctx_t *ctx,
                      const uint8_t *inner_frame,
                      size_t inner_len,
                      uint8_t *outer_packet,
                      size_t *outer_len,
                      uint32_t dst_vtep_ip);

/**
 * Decapsulate a VXLAN packet
 * 
 * @param ctx           VXLAN context
 * @param outer_packet  VXLAN packet
 * @param outer_len     Length of VXLAN packet
 * @param inner_frame   Output buffer for inner frame
 * @param inner_len     Output length of inner frame
 * @param src_vtep_ip   Source VTEP IP (output, network byte order)
 * @param vni           VNI from packet (output)
 * @return              0 on success, -1 on error
 */
int vxlan_decapsulate(vxlan_ctx_t *ctx,
                      const uint8_t *outer_packet,
                      size_t outer_len,
                      uint8_t *inner_frame,
                      size_t *inner_len,
                      uint32_t *src_vtep_ip,
                      uint32_t *vni);

/**
 * Learn MAC address mapping
 * 
 * @param ctx       VXLAN context
 * @param mac       MAC address
 * @param vtep_ip   Remote VTEP IP
 * @param vni       VNI
 * @return          0 on success, -1 on error
 */
int vxlan_mac_learn(vxlan_ctx_t *ctx, const uint8_t *mac, uint32_t vtep_ip, uint32_t vni);

/**
 * Lookup MAC address in learning table
 * 
 * @param ctx       VXLAN context
 * @param mac       MAC address
 * @param vni       VNI
 * @param vtep_ip   Output: Remote VTEP IP (network byte order)
 * @return          0 if found, -1 if not found
 */
int vxlan_mac_lookup(vxlan_ctx_t *ctx, const uint8_t *mac, uint32_t vni, uint32_t *vtep_ip);

/**
 * Age out old MAC entries
 * 
 * @param ctx   VXLAN context
 * @return      Number of entries aged out
 */
int vxlan_mac_age(vxlan_ctx_t *ctx);

/**
 * Get VXLAN statistics
 * 
 * @param ctx    VXLAN context
 * @param stats  Output statistics structure
 */
void vxlan_get_stats(vxlan_ctx_t *ctx, vxlan_stats_t *stats);

/**
 * Print VXLAN packet for debugging
 * 
 * @param packet    Packet data
 * @param len       Packet length
 * @param label     Description label
 */
void vxlan_dump_packet(const uint8_t *packet, size_t len, const char *label);

/**
 * Validate VXLAN header
 * 
 * @param vxlan_hdr     VXLAN header pointer
 * @return              true if valid, false otherwise
 */
bool vxlan_validate_header(const vxlan_hdr_t *vxlan_hdr);

/**
 * Calculate UDP source port from inner frame (for ECMP)
 * 
 * @param inner_frame   Inner Ethernet frame
 * @param inner_len     Frame length
 * @return              UDP source port in host byte order
 */
uint16_t vxlan_calc_src_port(const uint8_t *inner_frame, size_t inner_len);

/* ==================== Helper Macros ==================== */

#define VXLAN_VNI_TO_BYTES(vni, bytes) do { \
    (bytes)[0] = ((vni) >> 16) & 0xFF; \
    (bytes)[1] = ((vni) >> 8) & 0xFF; \
    (bytes)[2] = (vni) & 0xFF; \
} while(0)

#define VXLAN_BYTES_TO_VNI(bytes) \
    ((((uint32_t)(bytes)[0]) << 16) | (((uint32_t)(bytes)[1]) << 8) | ((uint32_t)(bytes)[2]))

#define MAC_TO_STR(mac, str) \
    snprintf(str, 18, "%02x:%02x:%02x:%02x:%02x:%02x", \
             (mac)[0], (mac)[1], (mac)[2], (mac)[3], (mac)[4], (mac)[5])

#define IP_TO_STR(ip, str) do { \
    struct in_addr addr; \
    addr.s_addr = ip; \
    strcpy(str, inet_ntoa(addr)); \
} while(0)

#endif /* VXLAN_H */
