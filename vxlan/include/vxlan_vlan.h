  
/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : vxlan_vlan.h  
 * Purpose     : Inner VLAN Tag Handling (RFC 7348 Section 6.1)
 *                Includes RFC 7348 requirements:
 *                 - Decapsulated frames with inner VLAN SHOULD be discarded
 *                 - VTEP SHOULD NOT include inner VLAN on tunnel packets
 *                 - Encapsulating VTEP SHOULD strip VLAN before encapsulation
 *****************************************************************************/


#ifndef VXLAN_VLAN_H
#define VXLAN_VLAN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* VLAN Constants */
#define VLAN_ETHERTYPE      0x8100  /* 802.1Q VLAN tag */
#define VLAN_TAG_SIZE       4       /* VLAN tag is 4 bytes */
#define VLAN_VID_MASK       0x0FFF  /* 12-bit VLAN ID mask */
#define VLAN_PCP_MASK       0xE000  /* 3-bit Priority Code Point */
#define VLAN_DEI_MASK       0x1000  /* 1-bit Drop Eligible Indicator */

/**
 * VLAN Tag Structure (802.1Q)
 * 
 * Format:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       EtherType = 0x8100      |PCP|D|        VLAN ID          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct {
    uint16_t tpid;      /* Tag Protocol Identifier (0x8100) */
    uint16_t tci;       /* Tag Control Information (PCP + DEI + VID) */
} __attribute__((packed)) vlan_tag_t;

/**
 * VLAN Configuration for VTEP
 */
typedef struct {
    bool     allow_inner_vlan;      /* Allow inner VLAN tags (default: false) */
    bool     strip_on_encap;        /* Strip VLAN before encap (default: true) */
    bool     discard_on_decap;      /* Discard with inner VLAN (default: true) */
    uint16_t vlan_id_map[4096];     /* VNI mapping for VLAN IDs (gateway mode) */
    bool     gateway_mode;          /* Enable VLAN-to-VNI gateway (default: false) */
} vlan_config_t;

/**
 * Check if frame has VLAN tag
 * 
 * @param frame     Ethernet frame
 * @param frame_len Frame length
 * @return          true if VLAN tagged, false otherwise
 */
bool vxlan_vlan_is_tagged(const uint8_t *frame, size_t frame_len);

/**
 * Get VLAN ID from tagged frame
 * 
 * @param frame     Ethernet frame (must be VLAN tagged)
 * @param vlan_id   Output: VLAN ID (12 bits)
 * @return          0 on success, -1 on error
 */
int vxlan_vlan_get_id(const uint8_t *frame, uint16_t *vlan_id);

/**
 * Strip VLAN tag from frame
 * 
 * @param frame         Input frame (VLAN tagged)
 * @param frame_len     Input frame length
 * @param output        Output buffer for untagged frame
 * @param output_len    Output: untagged frame length
 * @return              0 on success, -1 on error
 */
int vxlan_vlan_strip(const uint8_t *frame, 
                     size_t frame_len,
                     uint8_t *output, 
                     size_t *output_len);

/**
 * Add VLAN tag to frame
 * 
 * @param frame         Input frame (untagged)
 * @param frame_len     Input frame length
 * @param vlan_id       VLAN ID to add (12 bits, 0-4095)
 * @param priority      Priority Code Point (3 bits, 0-7)
 * @param output        Output buffer for tagged frame
 * @param output_len    Output: tagged frame length
 * @return              0 on success, -1 on error
 */
int vxlan_vlan_add(const uint8_t *frame,
                   size_t frame_len,
                   uint16_t vlan_id,
                   uint8_t priority,
                   uint8_t *output,
                   size_t *output_len);

/**
 * Validate VLAN tag (check if should be processed or discarded)
 * 
 * @param frame     Ethernet frame
 * @param frame_len Frame length
 * @param config    VLAN configuration
 * @return          0 if OK to process, -1 if should discard
 */
int vxlan_vlan_validate(const uint8_t *frame, 
                        size_t frame_len,
                        const vlan_config_t *config);

/**
 * Map VLAN ID to VNI (for gateway mode)
 * 
 * @param config    VLAN configuration
 * @param vlan_id   VLAN ID (input)
 * @param vni       VNI (output)
 * @return          0 on success, -1 if no mapping
 */
int vxlan_vlan_to_vni(const vlan_config_t *config,
                      uint16_t vlan_id,
                      uint32_t *vni);

/**
 * Map VNI to VLAN ID (for gateway mode)
 * 
 * @param config    VLAN configuration
 * @param vni       VNI (input)
 * @param vlan_id   VLAN ID (output)
 * @return          0 on success, -1 if no mapping
 */
int vxlan_vni_to_vlan(const vlan_config_t *config,
                      uint32_t vni,
                      uint16_t *vlan_id);

/**
 * Initialize VLAN configuration with RFC 7348 defaults
 * 
 * @param config    VLAN configuration to initialize
 */
void vxlan_vlan_config_init(vlan_config_t *config);

/**
 * Set VLAN-to-VNI mapping (gateway mode)
 * 
 * @param config    VLAN configuration
 * @param vlan_id   VLAN ID (0-4095)
 * @param vni       VNI to map to
 * @return          0 on success, -1 on error
 */
int vxlan_vlan_set_mapping(vlan_config_t *config,
                           uint16_t vlan_id,
                           uint32_t vni);

/**
 * Enable/disable gateway mode
 * 
 * @param config    VLAN configuration
 * @param enabled   true to enable gateway mode
 */
void vxlan_vlan_set_gateway_mode(vlan_config_t *config, bool enabled);

/**
 * Get VLAN tag details (for debugging)
 * 
 * @param frame     Ethernet frame
 * @param vlan_id   Output: VLAN ID
 * @param priority  Output: Priority (PCP)
 * @param dei       Output: Drop Eligible Indicator
 * @return          0 on success, -1 on error
 */
int vxlan_vlan_get_details(const uint8_t *frame,
                           uint16_t *vlan_id,
                           uint8_t *priority,
                           uint8_t *dei);

#endif /* VXLAN_VLAN_H */
