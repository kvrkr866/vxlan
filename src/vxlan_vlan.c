  
/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : vxlan_vlan.c  
 * Purpose     : Inner VLAN Tag Handling (RFC 7348 Section 6.1)
 *                 RFC 7348 Section 6.1 Compliance:
 *                 - Decapsulated frames with inner VLAN SHOULD be discarded
 *                 - VTEP SHOULD NOT include inner VLAN on tunnel packets
 *                 - Encapsulating VTEP SHOULD strip VLAN before encapsulation
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/vxlan_vlan.h"
#include "../include/vxlan.h"

/**
 * Initialize VLAN configuration with RFC 7348 defaults
 */
void vxlan_vlan_config_init(vlan_config_t *config) {
    if (!config) {
        return;
    }
    
    memset(config, 0, sizeof(vlan_config_t));
    
    /* RFC 7348 Section 6.1 defaults */
    config->allow_inner_vlan = false;   /* SHOULD NOT include inner VLAN */
    config->strip_on_encap = true;      /* SHOULD strip VLAN before encap */
    config->discard_on_decap = true;    /* SHOULD discard with inner VLAN */
    config->gateway_mode = false;       /* Gateway mode disabled by default */
    
    /* Initialize VLAN-to-VNI mapping table (0 = no mapping) */
    for (int i = 0; i < 4096; i++) {
        config->vlan_id_map[i] = 0;
    }
}

/**
 * Check if frame has VLAN tag (802.1Q)
 */
bool vxlan_vlan_is_tagged(const uint8_t *frame, size_t frame_len) {
    if (!frame || frame_len < 14) {
        return false;
    }
    
    /* Check EtherType field (bytes 12-13) */
    uint16_t ethertype = (frame[12] << 8) | frame[13];
    
    return (ethertype == VLAN_ETHERTYPE);
}

/**
 * Get VLAN ID from tagged frame
 */
int vxlan_vlan_get_id(const uint8_t *frame, uint16_t *vlan_id) {
    if (!frame || !vlan_id) {
        return -1;
    }
    
    if (!vxlan_vlan_is_tagged(frame, 18)) {
        return -1;
    }
    
    /* VLAN tag is at bytes 14-15 (TCI field) */
    uint16_t tci = (frame[14] << 8) | frame[15];
    
    /* Extract VLAN ID (lower 12 bits) */
    *vlan_id = tci & VLAN_VID_MASK;
    
    return 0;
}

/**
 * Get VLAN tag details
 */
int vxlan_vlan_get_details(const uint8_t *frame,
                           uint16_t *vlan_id,
                           uint8_t *priority,
                           uint8_t *dei) {
    if (!frame || !vlan_id || !priority || !dei) {
        return -1;
    }
    
    if (!vxlan_vlan_is_tagged(frame, 18)) {
        return -1;
    }
    
    /* TCI field at bytes 14-15 */
    uint16_t tci = (frame[14] << 8) | frame[15];
    
    /* Extract fields */
    *vlan_id = tci & VLAN_VID_MASK;              /* Bits 0-11 */
    *dei = (tci & VLAN_DEI_MASK) ? 1 : 0;        /* Bit 12 */
    *priority = (tci & VLAN_PCP_MASK) >> 13;     /* Bits 13-15 */
    
    return 0;
}

/**
 * Strip VLAN tag from frame
 * 
 * Original frame format:
 * [Dst MAC (6)] [Src MAC (6)] [0x8100 (2)] [TCI (2)] [EtherType (2)] [Payload]
 * 
 * Stripped frame format:
 * [Dst MAC (6)] [Src MAC (6)] [EtherType (2)] [Payload]
 */
int vxlan_vlan_strip(const uint8_t *frame, 
                     size_t frame_len,
                     uint8_t *output, 
                     size_t *output_len) {
    if (!frame || !output || !output_len) {
        return -1;
    }
    
    /* Must be VLAN tagged */
    if (!vxlan_vlan_is_tagged(frame, frame_len)) {
        fprintf(stderr, "Frame is not VLAN tagged\n");
        return -1;
    }
    
    /* Minimum tagged frame: 18 bytes (14 + 4 for VLAN tag) */
    if (frame_len < 18) {
        return -1;
    }
    
    /* Copy destination MAC (6 bytes) */
    memcpy(output, frame, 6);
    
    /* Copy source MAC (6 bytes) */
    memcpy(output + 6, frame + 6, 6);
    
    /* Copy EtherType (2 bytes) - this was at offset 16 after VLAN tag */
    memcpy(output + 12, frame + 16, 2);
    
    /* Copy payload (everything after EtherType) */
    size_t payload_size = frame_len - 18;
    if (payload_size > 0) {
        memcpy(output + 14, frame + 18, payload_size);
    }
    
    *output_len = frame_len - VLAN_TAG_SIZE;
    
    return 0;
}

/**
 * Add VLAN tag to frame
 * 
 * Untagged frame format:
 * [Dst MAC (6)] [Src MAC (6)] [EtherType (2)] [Payload]
 * 
 * Tagged frame format:
 * [Dst MAC (6)] [Src MAC (6)] [0x8100 (2)] [TCI (2)] [EtherType (2)] [Payload]
 */
int vxlan_vlan_add(const uint8_t *frame,
                   size_t frame_len,
                   uint16_t vlan_id,
                   uint8_t priority,
                   uint8_t *output,
                   size_t *output_len) {
    if (!frame || !output || !output_len) {
        return -1;
    }
    
    /* Validate VLAN ID (12 bits, 0-4095) */
    if (vlan_id > 4095) {
        fprintf(stderr, "Invalid VLAN ID: %u (max 4095)\n", vlan_id);
        return -1;
    }
    
    /* Validate priority (3 bits, 0-7) */
    if (priority > 7) {
        fprintf(stderr, "Invalid priority: %u (max 7)\n", priority);
        return -1;
    }
    
    /* Frame must be at least 14 bytes */
    if (frame_len < 14) {
        return -1;
    }
    
    /* Don't double-tag */
    if (vxlan_vlan_is_tagged(frame, frame_len)) {
        fprintf(stderr, "Frame is already VLAN tagged\n");
        return -1;
    }
    
    /* Copy destination MAC (6 bytes) */
    memcpy(output, frame, 6);
    
    /* Copy source MAC (6 bytes) */
    memcpy(output + 6, frame + 6, 6);
    
    /* Insert VLAN tag (4 bytes) */
    /* TPID: 0x8100 */
    output[12] = 0x81;
    output[13] = 0x00;
    
    /* TCI: [PCP (3 bits)] [DEI (1 bit)] [VID (12 bits)] */
    uint16_t tci = (priority << 13) | vlan_id;
    output[14] = (tci >> 8) & 0xFF;
    output[15] = tci & 0xFF;
    
    /* Copy original EtherType (2 bytes) */
    memcpy(output + 16, frame + 12, 2);
    
    /* Copy payload */
    size_t payload_size = frame_len - 14;
    if (payload_size > 0) {
        memcpy(output + 18, frame + 14, payload_size);
    }
    
    *output_len = frame_len + VLAN_TAG_SIZE;
    
    return 0;
}

/**
 * Validate VLAN tag - check if frame should be processed or discarded
 * 
 * RFC 7348 Section 6.1:
 * "Decapsulated VXLAN frames with the inner VLAN tag SHOULD be discarded
 *  unless configured otherwise."
 */
int vxlan_vlan_validate(const uint8_t *frame, 
                        size_t frame_len,
                        const vlan_config_t *config) {
    if (!frame || !config) {
        return -1;
    }
    
    bool is_tagged = vxlan_vlan_is_tagged(frame, frame_len);
    
    /* If frame has VLAN tag and we're configured to discard */
    if (is_tagged && config->discard_on_decap && !config->allow_inner_vlan) {
        uint16_t vlan_id;
        if (vxlan_vlan_get_id(frame, &vlan_id) == 0) {
            fprintf(stderr, "Discarding frame with inner VLAN tag (VLAN %u) per RFC 7348\n",
                    vlan_id);
        }
        return -1; /* Should discard */
    }
    
    return 0; /* OK to process */
}

/**
 * Map VLAN ID to VNI (gateway mode)
 */
int vxlan_vlan_to_vni(const vlan_config_t *config,
                      uint16_t vlan_id,
                      uint32_t *vni) {
    if (!config || !vni) {
        return -1;
    }
    
    if (vlan_id > 4095) {
        return -1;
    }
    
    if (!config->gateway_mode) {
        fprintf(stderr, "Gateway mode not enabled\n");
        return -1;
    }
    
    uint32_t mapped_vni = config->vlan_id_map[vlan_id];
    
    if (mapped_vni == 0) {
        /* No mapping configured */
        return -1;
    }
    
    *vni = mapped_vni;
    return 0;
}

/**
 * Map VNI to VLAN ID (gateway mode)
 */
int vxlan_vni_to_vlan(const vlan_config_t *config,
                      uint32_t vni,
                      uint16_t *vlan_id) {
    if (!config || !vlan_id) {
        return -1;
    }
    
    if (!config->gateway_mode) {
        fprintf(stderr, "Gateway mode not enabled\n");
        return -1;
    }
    
    /* Search for VNI in mapping table */
    for (int i = 0; i < 4096; i++) {
        if (config->vlan_id_map[i] == vni) {
            *vlan_id = i;
            return 0;
        }
    }
    
    /* No mapping found */
    return -1;
}

/**
 * Set VLAN-to-VNI mapping
 */
int vxlan_vlan_set_mapping(vlan_config_t *config,
                           uint16_t vlan_id,
                           uint32_t vni) {
    if (!config) {
        return -1;
    }
    
    if (vlan_id > 4095) {
        fprintf(stderr, "Invalid VLAN ID: %u\n", vlan_id);
        return -1;
    }
    
    if (vni > VXLAN_VNI_MAX) {
        fprintf(stderr, "Invalid VNI: %u\n", vni);
        return -1;
    }
    
    config->vlan_id_map[vlan_id] = vni;
    
    printf("VLAN mapping configured: VLAN %u → VNI %u\n", vlan_id, vni);
    
    return 0;
}

/**
 * Enable/disable gateway mode
 */
void vxlan_vlan_set_gateway_mode(vlan_config_t *config, bool enabled) {
    if (!config) {
        return;
    }
    
    config->gateway_mode = enabled;
    
    if (enabled) {
        /* In gateway mode, we need to handle VLANs differently */
        config->allow_inner_vlan = true;    /* Allow VLANs for mapping */
        config->discard_on_decap = false;   /* Don't auto-discard */
        printf("VXLAN Gateway mode: ENABLED\n");
    } else {
        /* Standard VTEP mode - RFC 7348 defaults */
        config->allow_inner_vlan = false;
        config->discard_on_decap = true;
        printf("VXLAN Gateway mode: DISABLED (standard VTEP mode)\n");
    }
}
