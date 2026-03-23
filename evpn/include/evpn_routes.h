
 /*****************************************************************************
 * Project     : EVPN Protocol Implementation (RFC 8365)
 * Description : Part of minimal implementation of EVPN
 *                 * Author      : RK (kvrkr866@gmail.com)
 * File name   : evpn_routes.h  
 * Purpose     : This implementation provides - EVPN Route Types Processing
 *                RFC 8365 - EVPN Route Types 1-5
 *                RFC 7432 - BGP MPLS-Based Ethernet VPN
 * 
 *              This module handles encoding/decoding of 
 *                 EVPN NLRI for all route types
  *****************************************************************************/

#ifndef EVPN_ROUTES_H
#define EVPN_ROUTES_H

#include <stdint.h>
#include <stdbool.h>
#include "evpn.h"

/* EVPN NLRI Constants */
#define EVPN_NLRI_MAX_SIZE      256

/* EVPN Route Type Lengths (excluding route type byte) */
#define EVPN_TYPE1_MIN_LENGTH   23   /* Ethernet AD route */
#define EVPN_TYPE2_MIN_LENGTH   33   /* MAC/IP Advertisement */
#define EVPN_TYPE3_LENGTH       17   /* Inclusive Multicast */
#define EVPN_TYPE4_LENGTH       23   /* Ethernet Segment */
#define EVPN_TYPE5_MIN_LENGTH   34   /* IP Prefix */

/* Label Constants */
#define EVPN_LABEL_BITS         20
#define EVPN_LABEL_MAX          0xFFFFF

/**
 * EVPN NLRI Header (common to all route types)
 */
typedef struct {
    uint8_t route_type;        /* Route type (1-5) */
    uint8_t length;            /* Length of NLRI (excluding this byte) */
} __attribute__((packed)) evpn_nlri_header_t;

/* Function Prototypes */

/* ============================================================
 * Type 2 Routes - MAC/IP Advertisement (CRITICAL)
 * ============================================================ */

/**
 * Encode Type 2 route to EVPN NLRI format
 * 
 * @param route     MAC/IP advertisement route
 * @param buf       Output buffer
 * @param buf_size  Buffer size
 * @param len       Output: NLRI length
 * @return          0 on success, -1 on error
 */
int evpn_encode_type2_route(const evpn_mac_ip_route_t *route,
                            uint8_t *buf, size_t buf_size, size_t *len);

/**
 * Decode Type 2 route from EVPN NLRI
 * 
 * @param nlri      NLRI data (starts after route type)
 * @param nlri_len  NLRI length
 * @param route     Output: MAC/IP route
 * @return          0 on success, -1 on error
 */
int evpn_decode_type2_route(const uint8_t *nlri, size_t nlri_len,
                            evpn_mac_ip_route_t *route);

/**
 * Advertise local MAC/IP to BGP peers
 * 
 * @param ctx       EVPN context
 * @param mac       MAC address
 * @param ip        IP address (0 if MAC-only)
 * @param vni       VNI
 * @return          0 on success, -1 on error
 */
int evpn_advertise_mac_ip(evpn_ctx_t *ctx, const uint8_t *mac, 
                          uint32_t ip, uint32_t vni);

/**
 * Withdraw MAC/IP route
 * 
 * @param ctx       EVPN context
 * @param mac       MAC address
 * @param vni       VNI
 * @return          0 on success, -1 on error
 */
int evpn_withdraw_mac_ip(evpn_ctx_t *ctx, const uint8_t *mac, uint32_t vni);

/**
 * Process received Type 2 route
 * 
 * @param ctx       EVPN context
 * @param route     MAC/IP route
 * @param next_hop  Next hop (VTEP IP)
 * @param withdraw  Is this a withdrawal?
 * @return          0 on success, -1 on error
 */
int evpn_process_mac_ip_route(evpn_ctx_t *ctx, 
                              const evpn_mac_ip_route_t *route,
                              uint32_t next_hop,
                              bool withdraw);

/* ============================================================
 * Type 3 Routes - Inclusive Multicast (CRITICAL)
 * ============================================================ */

/**
 * Encode Type 3 route to EVPN NLRI format
 * 
 * @param route     Inclusive multicast route
 * @param buf       Output buffer
 * @param buf_size  Buffer size
 * @param len       Output: NLRI length
 * @return          0 on success, -1 on error
 */
int evpn_encode_type3_route(const evpn_inclusive_mcast_route_t *route,
                            uint8_t *buf, size_t buf_size, size_t *len);

/**
 * Decode Type 3 route from EVPN NLRI
 * 
 * @param nlri      NLRI data
 * @param nlri_len  NLRI length
 * @param route     Output: Inclusive multicast route
 * @return          0 on success, -1 on error
 */
int evpn_decode_type3_route(const uint8_t *nlri, size_t nlri_len,
                            evpn_inclusive_mcast_route_t *route);

/**
 * Advertise Inclusive Multicast route
 * 
 * @param ctx       EVPN context
 * @param vni       VNI
 * @return          0 on success, -1 on error
 */
int evpn_advertise_inclusive_mcast(evpn_ctx_t *ctx, uint32_t vni);

/**
 * Withdraw Inclusive Multicast route
 * 
 * @param ctx       EVPN context
 * @param vni       VNI
 * @return          0 on success, -1 on error
 */
int evpn_withdraw_inclusive_mcast(evpn_ctx_t *ctx, uint32_t vni);

/**
 * Process received Type 3 route
 * 
 * @param ctx       EVPN context
 * @param route     Inclusive multicast route
 * @param next_hop  Next hop (originating VTEP IP)
 * @param withdraw  Is this a withdrawal?
 * @return          0 on success, -1 on error
 */
int evpn_process_inclusive_mcast_route(evpn_ctx_t *ctx,
                                       const evpn_inclusive_mcast_route_t *route,
                                       uint32_t next_hop,
                                       bool withdraw);

/* ============================================================
 * Type 1 Routes - Ethernet Auto-Discovery 
 * ============================================================ */

int evpn_encode_type1_route(const evpn_ethernet_ad_route_t *route,
                            uint8_t *buf, size_t buf_size, size_t *len);
int evpn_decode_type1_route(const uint8_t *nlri, size_t nlri_len,
                            evpn_ethernet_ad_route_t *route);

/* ============================================================
 * Type 4 Routes - Ethernet Segment 
 * ============================================================ */

int evpn_encode_type4_route(const evpn_ethernet_segment_route_t *route,
                            uint8_t *buf, size_t buf_size, size_t *len);
int evpn_decode_type4_route(const uint8_t *nlri, size_t nlri_len,
                            evpn_ethernet_segment_route_t *route);

/* ============================================================
 * Generic NLRI Processing
 * ============================================================ */

/**
 * Process EVPN NLRI (dispatches to appropriate type handler)
 * 
 * @param ctx       EVPN context
 * @param nlri      NLRI data
 * @param nlri_len  NLRI length
 * @param next_hop  Next hop IP
 * @param withdraw  Is this a withdrawal?
 * @return          0 on success, -1 on error
 */
int evpn_process_nlri(evpn_ctx_t *ctx, const uint8_t *nlri, size_t nlri_len,
                     uint32_t next_hop, bool withdraw);

/**
 * Build BGP UPDATE message with EVPN route
 * 
 * @param ctx       EVPN context
 * @param nlri      EVPN NLRI data
 * @param nlri_len  NLRI length
 * @param next_hop  Next hop IP
 * @param buf       Output buffer
 * @param buf_size  Buffer size
 * @param msg_len   Output: Message length
 * @return          0 on success, -1 on error
 */
int evpn_build_update_message(evpn_ctx_t *ctx,
                              const uint8_t *nlri, size_t nlri_len,
                              uint32_t next_hop,
                              uint8_t *buf, size_t buf_size,
                              size_t *msg_len);

/**
 * Build BGP withdrawal message for EVPN route
 * 
 * @param ctx       EVPN context
 * @param nlri      EVPN NLRI data
 * @param nlri_len  NLRI length
 * @param buf       Output buffer
 * @param buf_size  Buffer size
 * @param msg_len   Output: Message length
 * @return          0 on success, -1 on error
 */
int evpn_build_withdrawal_message(evpn_ctx_t *ctx,
                                  const uint8_t *nlri, size_t nlri_len,
                                  uint8_t *buf, size_t buf_size,
                                  size_t *msg_len);

/* ============================================================
 * Helper Functions
 * ============================================================ */

/**
 * Encode MPLS label (20 bits)
 * 
 * @param label     Label value
 * @param buf       Output buffer (3 bytes)
 */
void evpn_encode_label(uint32_t label, uint8_t *buf);

/**
 * Decode MPLS label
 * 
 * @param buf       Input buffer (3 bytes)
 * @return          Label value
 */
uint32_t evpn_decode_label(const uint8_t *buf);

/**
 * Encode ESI (10 bytes)
 * 
 * @param esi       ESI structure
 * @param buf       Output buffer (10 bytes)
 */
void evpn_encode_esi(const evpn_esi_t *esi, uint8_t *buf);

/**
 * Decode ESI
 * 
 * @param buf       Input buffer (10 bytes)
 * @param esi       Output: ESI structure
 */
void evpn_decode_esi(const uint8_t *buf, evpn_esi_t *esi);

/**
 * Encode Route Distinguisher
 * 
 * @param rd        RD structure
 * @param buf       Output buffer (8 bytes)
 */
void evpn_encode_rd(const evpn_rd_t *rd, uint8_t *buf);

/**
 * Decode Route Distinguisher
 * 
 * @param buf       Input buffer (8 bytes)
 * @param rd        Output: RD structure
 */
void evpn_decode_rd(const uint8_t *buf, evpn_rd_t *rd);

/**
 * Get route type name
 * 
 * @param type      Route type (1-5)
 * @return          Route type name string
 */
const char *evpn_route_type_name(evpn_route_type_t type);

/**
 * Validate EVPN NLRI
 * 
 * @param nlri      NLRI data
 * @param nlri_len  NLRI length
 * @return          true if valid, false otherwise
 */
bool evpn_validate_nlri(const uint8_t *nlri, size_t nlri_len);


/* ============================================================
 * Type 5 Routes - IP Prefix Route (Feature 1)
 * RFC 9136 - IP Prefix Advertisement in EVPN
 * ============================================================ */

/**
 * Type 5 Route - IP Prefix Route Structure
 * 
 * Used for inter-subnet routing (symmetric/asymmetric IRB)
 */
typedef struct {
    evpn_rd_t rd;              /* Route Distinguisher */
    evpn_esi_t esi;            /* ESI (0 if not multi-homed) */
    uint32_t ethernet_tag;     /* Ethernet Tag ID */
    uint8_t ip_prefix_len;     /* IP prefix length (0-32 for IPv4) */
    uint32_t ip_prefix;        /* IP prefix (IPv4) */
    uint32_t gw_ip;            /* Gateway IP address */
    uint32_t label;            /* VNI/MPLS label */
} evpn_ip_prefix_route_t;

/**
 * Encode Type 5 route to BGP NLRI format
 */
int evpn_encode_type5_route(const evpn_ip_prefix_route_t *route,
                            uint8_t *buf, size_t buf_size, size_t *len);

/**
 * Decode Type 5 route from BGP NLRI
 */
int evpn_decode_type5_route(const uint8_t *nlri, size_t nlri_len,
                            evpn_ip_prefix_route_t *route);

/**
 * Advertise IP prefix via Type 5 route
 * 
 * @param ctx           EVPN context
 * @param ip_prefix     IP prefix
 * @param prefix_len    Prefix length
 * @param gw_ip         Gateway IP
 * @param vni           VNI
 * @return              0 on success, -1 on error
 */
int evpn_advertise_ip_prefix(evpn_ctx_t *ctx, uint32_t ip_prefix,
                             uint8_t prefix_len, uint32_t gw_ip, uint32_t vni);

/**
 * Withdraw IP prefix
 */
int evpn_withdraw_ip_prefix(evpn_ctx_t *ctx, uint32_t ip_prefix,
                            uint8_t prefix_len, uint32_t vni);

/**
 * Process received Type 5 route
 */
int evpn_process_ip_prefix_route(evpn_ctx_t *ctx,
                                 const evpn_ip_prefix_route_t *route,
                                 uint32_t next_hop, bool withdraw);

/**
 * Install IP prefix route in routing table
 */
int evpn_install_ip_route(evpn_ctx_t *ctx, uint32_t ip_prefix,
                          uint8_t prefix_len, uint32_t next_hop, uint32_t vni);

/**
 * Remove IP prefix route from routing table
 */
int evpn_remove_ip_route(evpn_ctx_t *ctx, uint32_t ip_prefix,
                        uint8_t prefix_len, uint32_t vni);


/* ============================================================
 * MAC Mobility (Feature 2)
 * RFC 7432 Section 15 - MAC Mobility
 * ============================================================ */

/**
 * MAC Mobility Extended Community
 */
typedef struct {
    bool sticky;              /* Sticky MAC flag */
    uint32_t sequence;        /* Sequence number */
} evpn_mac_mobility_t;

/**
 * Advertise MAC with mobility sequence number
 */
int evpn_advertise_mac_with_seq(evpn_ctx_t *ctx, const uint8_t *mac,
                                uint32_t ip, uint32_t vni, uint32_t seq);

/**
 * Detect MAC mobility (move between VTEPs)
 */
bool evpn_detect_mac_move(evpn_ctx_t *ctx, const uint8_t *mac, uint32_t vni,
                         uint32_t new_vtep, uint32_t *old_vtep);

/**
 * Handle MAC mobility event
 */
int evpn_handle_mac_move(evpn_ctx_t *ctx, const uint8_t *mac, uint32_t vni,
                        uint32_t old_vtep, uint32_t new_vtep);

/**
 * Get MAC mobility sequence number
 */
uint32_t evpn_get_mac_sequence(evpn_ctx_t *ctx, const uint8_t *mac, uint32_t vni);

/**
 * Increment MAC mobility sequence
 */
uint32_t evpn_increment_mac_sequence(evpn_ctx_t *ctx, const uint8_t *mac, uint32_t vni);

/**
 * Check if MAC move should be allowed (loop prevention)
 */
bool evpn_should_allow_mac_move(evpn_ctx_t *ctx, const uint8_t *mac, uint32_t vni,
                               uint32_t old_seq, uint32_t new_seq);

/* ============================================================
 * ARP Suppression (Feature 3)
 * RFC 7432 Section 10 - ARP and ND Extended Community
 * ============================================================ */

/**
 * ARP cache entry
 */
typedef struct {
    uint32_t ip;              /* IP address */
    uint8_t mac[6];           /* MAC address */
    uint32_t vni;             /* VNI */
    time_t timestamp;         /* Last update */
} evpn_arp_entry_t;

/**
 * Enable ARP suppression for a VNI
 */
int evpn_enable_arp_suppression(evpn_ctx_t *ctx, uint32_t vni);

/**
 * Add entry to ARP cache (learned via BGP)
 */
int evpn_arp_cache_add(evpn_ctx_t *ctx, uint32_t ip, const uint8_t *mac, uint32_t vni);

/**
 * Lookup IP in ARP cache
 */
int evpn_arp_cache_lookup(evpn_ctx_t *ctx, uint32_t ip, uint32_t vni,
                          uint8_t *mac_out);

/**
 * Handle ARP request (suppress if we can answer)
 */
bool evpn_handle_arp_request(evpn_ctx_t *ctx, uint32_t target_ip, uint32_t vni,
                            uint8_t *reply_mac);

/**
 * Generate ARP reply locally
 */
int evpn_generate_arp_reply(evpn_ctx_t *ctx, uint32_t src_ip, const uint8_t *src_mac,
                           uint32_t target_ip, const uint8_t *target_mac,
                           uint8_t *reply, size_t *reply_len);

/**
 * Get ARP suppression statistics
 */
int evpn_get_arp_stats(evpn_ctx_t *ctx, uint32_t vni,
                      uint64_t *requests_received,
                      uint64_t *requests_suppressed,
                      uint64_t *cache_entries);

/* ============================================================
 * Route Policies (Feature 4)
 * Import/Export Filtering
 * ============================================================ */

typedef enum {
    EVPN_POLICY_PERMIT,
    EVPN_POLICY_DENY
} evpn_policy_action_t;

typedef struct {
    char name[64];
    evpn_policy_action_t action;
    evpn_route_type_t route_type;  // 0 = all types
    uint32_t vni;                   // 0 = all VNIs
    bool active;
} evpn_route_policy_t;

/**
 * Create route policy
 */
int evpn_create_policy(evpn_ctx_t *ctx, const char *name,
                       evpn_policy_action_t action);

/**
 * Apply import policy to received route
 */
bool evpn_apply_import_policy(evpn_ctx_t *ctx, evpn_route_type_t type,
                              uint32_t vni);

/**
 * Apply export policy to advertised route
 */
bool evpn_apply_export_policy(evpn_ctx_t *ctx, evpn_route_type_t type,
                              uint32_t vni);

#endif /* EVPN_ROUTES_H */
