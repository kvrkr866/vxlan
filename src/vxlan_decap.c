
/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : vxlan_decap.c    
 * Purpose     : VXLAN Decapsulation Logic 
 *                Extracts inner Ethernet frames from VXLAN packets
 *****************************************************************************/

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "../include/vxlan.h"
#include "../include/vxlan_utils.h"

/**
 * Validate outer IP header
 */
static int validate_ip_header(const ip_hdr_t *ip_hdr, size_t remaining_len) {
    if (remaining_len < sizeof(ip_hdr_t)) {
        return -1;
    }
    
    /* Check version (should be 4) */
    if ((ip_hdr->ver_ihl >> 4) != 4) {
        return -1;
    }
    
    /* Check protocol (should be UDP = 17) */
    if (ip_hdr->protocol != 17) {
        return -1;
    }
    
    /* Verify IP checksum (optional but recommended) */
    uint16_t received_checksum = ip_hdr->checksum;
    ip_hdr_t *ip_copy = (ip_hdr_t *)ip_hdr;
    ip_copy->checksum = 0;
    uint16_t calculated_checksum = ip_checksum(ip_hdr, sizeof(ip_hdr_t));
    ip_copy->checksum = received_checksum;
    
    if (received_checksum != calculated_checksum) {
        fprintf(stderr, "IP checksum mismatch: received=0x%04x, calculated=0x%04x\n",
                ntohs(received_checksum), ntohs(calculated_checksum));
        /* Don't fail - some systems may have checksum offload */
    }
    
    return 0;
}

/**
 * Validate outer UDP header with checksum verification
 * 
 * RFC 7348 Requirements:
 * - UDP checksum SHOULD be transmitted as zero
 * - When received with zero checksum, MUST be accepted
 * - When non-zero, MUST be correctly calculated
 * - Receiver MAY verify checksum; if verification fails, MUST drop
 */
static int validate_udp_header(const udp_hdr_t *udp_hdr, 
                               const ip_hdr_t *ip_hdr,
                               size_t remaining_len, 
                               uint16_t expected_port,
                               bool verify_checksum) {
    if (remaining_len < sizeof(udp_hdr_t)) {
        return -1;
    }
    
    /* Check destination port (should be VXLAN port, default 4789) */
    if (ntohs(udp_hdr->dst_port) != expected_port) {
        fprintf(stderr, "UDP port mismatch: expected=%u, got=%u\n",
                expected_port, ntohs(udp_hdr->dst_port));
        return -1;
    }
    
    /* RFC 7348: UDP checksum MUST be accepted when zero */
    if (udp_hdr->checksum == 0) {
        /* Zero checksum is valid and MUST be accepted */
        return 0;
    }
    
    /* RFC 7348: Receiver MAY verify non-zero checksum */
    if (verify_checksum) {
        /* Calculate expected checksum with pseudo-header */
        uint16_t udp_len = ntohs(udp_hdr->length);
        
        /* Build pseudo-header for checksum calculation */
        struct {
            uint32_t src_ip;
            uint32_t dst_ip;
            uint8_t  zero;
            uint8_t  protocol;
            uint16_t udp_length;
        } __attribute__((packed)) pseudo_hdr;
        
        pseudo_hdr.src_ip = ip_hdr->src_ip;
        pseudo_hdr.dst_ip = ip_hdr->dst_ip;
        pseudo_hdr.zero = 0;
        pseudo_hdr.protocol = 17; /* UDP */
        pseudo_hdr.udp_length = udp_hdr->length;
        
        /* Calculate checksum over pseudo-header + UDP header + data */
        uint32_t sum = 0;
        const uint16_t *ptr;
        size_t count;
        
        /* Add pseudo-header */
        ptr = (const uint16_t *)&pseudo_hdr;
        count = sizeof(pseudo_hdr);
        while (count > 1) {
            sum += *ptr++;
            count -= 2;
        }
        
        /* Add UDP header and payload */
        ptr = (const uint16_t *)udp_hdr;
        count = udp_len;
        
        /* Save original checksum and set to 0 for calculation */
        uint16_t original_checksum = udp_hdr->checksum;
        ((udp_hdr_t *)udp_hdr)->checksum = 0;
        
        while (count > 1) {
            sum += *ptr++;
            count -= 2;
        }
        
        /* Add odd byte if present */
        if (count > 0) {
            sum += *(const uint8_t *)ptr;
        }
        
        /* Fold 32-bit sum to 16 bits */
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        uint16_t calculated_checksum = ~sum;
        
        /* Restore original checksum */
        ((udp_hdr_t *)udp_hdr)->checksum = original_checksum;
        
        /* RFC 7348: If verification fails, packet MUST be dropped */
        if (calculated_checksum != original_checksum) {
            fprintf(stderr, "UDP checksum verification FAILED (RFC 7348 violation):\n");
            fprintf(stderr, "  Expected: 0x%04x\n", ntohs(original_checksum));
            fprintf(stderr, "  Calculated: 0x%04x\n", ntohs(calculated_checksum));
            fprintf(stderr, "  Packet MUST be dropped per RFC 7348\n");
            return -1; /* MUST drop packet */
        }
        
        /* RFC 7348: If verification succeeds, MUST be accepted */
        return 0;
    }
    
    /* Checksum verification disabled - accept non-zero checksum without validation */
    return 0;

}


/**
 * Parse VXLAN header and extract VNI
 */
static int parse_vxlan_header(const vxlan_hdr_t *vxlan_hdr, 
                              uint32_t *vni_out,
                              size_t remaining_len) {
    if (remaining_len < sizeof(vxlan_hdr_t)) {
        return -1;
    }
    
    /* Validate VXLAN header */
    if (!vxlan_validate_header(vxlan_hdr)) {
        fprintf(stderr, "Invalid VXLAN header: I-flag not set or reserved bits wrong\n");
        return -1;
    }
    
    /* Extract VNI (24-bit network byte order) */
    *vni_out = VXLAN_BYTES_TO_VNI(vxlan_hdr->vni);
    
    /* Check if VNI is valid */
    if (*vni_out > VXLAN_VNI_MAX) {
        fprintf(stderr, "Invalid VNI: %u (max is %u)\n", *vni_out, VXLAN_VNI_MAX);
        return -1;
    }
    
    return 0;
}

/**
 * Main decapsulation function
 * 
 * Extracts inner Ethernet frame from VXLAN packet
 */
int vxlan_decapsulate(vxlan_ctx_t *ctx,
                      const uint8_t *outer_packet,
                      size_t outer_len,
                      uint8_t *inner_frame,
                      size_t *inner_len,
                      uint32_t *src_vtep_ip,
                      uint32_t *vni) {
    
    /* Validate inputs */
    if (!ctx || !outer_packet || !inner_frame || !inner_len || !src_vtep_ip || !vni) {
        return -1;
    }
    
    /* Minimum packet size check */
    size_t min_size = sizeof(eth_hdr_t) + sizeof(ip_hdr_t) + 
                      sizeof(udp_hdr_t) + sizeof(vxlan_hdr_t) + 
                      sizeof(eth_hdr_t); /* Inner Ethernet header at minimum */
    
    if (outer_len < min_size) {
        fprintf(stderr, "Packet too small: %zu bytes (minimum %zu)\n", 
                outer_len, min_size);
        return -1;
    }
    
    const uint8_t *pkt = outer_packet;
    size_t offset = 0;
    size_t remaining = outer_len;
    
    /* 1. Skip Outer Ethernet Header (we already know it's for us) */
    const eth_hdr_t *outer_eth = (const eth_hdr_t *)(pkt + offset);
    offset += sizeof(eth_hdr_t);
    remaining -= sizeof(eth_hdr_t);
    
    /* Verify it's an IPv4 packet */
    if (ntohs(outer_eth->ether_type) != 0x0800) {
        fprintf(stderr, "Not an IPv4 packet: ethertype=0x%04x\n", 
                ntohs(outer_eth->ether_type));
        return -1;
    }
    
    /* 2. Parse and Validate Outer IP Header */
    const ip_hdr_t *outer_ip = (const ip_hdr_t *)(pkt + offset);
    if (validate_ip_header(outer_ip, remaining) != 0) {
        fprintf(stderr, "Invalid outer IP header\n");
        return -1;
    }
    
    /* Extract source VTEP IP */
    *src_vtep_ip = outer_ip->src_ip;
    
    offset += sizeof(ip_hdr_t);
    remaining -= sizeof(ip_hdr_t);
    
    /* 3. Parse and Validate Outer UDP Header */
    const udp_hdr_t *outer_udp = (const udp_hdr_t *)(pkt + offset);
    if (validate_udp_header(outer_udp, outer_ip, remaining, 
                           ctx->vtep.udp_port, ctx->vtep.checksum_enabled) != 0) {
        fprintf(stderr, "Invalid outer UDP header\n");
        return -1;
    }
    
    offset += sizeof(udp_hdr_t);
    remaining -= sizeof(udp_hdr_t);
    
    /* 4. Parse VXLAN Header */
    const vxlan_hdr_t *vxlan_hdr = (const vxlan_hdr_t *)(pkt + offset);
    if (parse_vxlan_header(vxlan_hdr, vni, remaining) != 0) {
        fprintf(stderr, "Invalid VXLAN header\n");
        return -1;
    }
    
    offset += sizeof(vxlan_hdr_t);
    remaining -= sizeof(vxlan_hdr_t);
    
    /* 5. Check VNI matches our VTEP (if configured for single VNI) */
    if (ctx->vtep.vni != 0 && *vni != ctx->vtep.vni) {
        fprintf(stderr, "VNI mismatch: expected=%u, got=%u\n", 
                ctx->vtep.vni, *vni);
        return -1;
    }
    
    /* 6. Extract Inner Ethernet Frame */
    const eth_hdr_t *inner_eth = (const eth_hdr_t *)(pkt + offset);
    
    if (remaining < sizeof(eth_hdr_t)) {
        fprintf(stderr, "Inner frame too small: %zu bytes\n", remaining);
        return -1;
    }
    
    /* Copy entire inner frame (Ethernet header + payload) */
    *inner_len = remaining;
    
    if (*inner_len > ETH_DATA_LEN) {
        fprintf(stderr, "Inner frame too large: %zu bytes\n", *inner_len);
        return -1;
    }
    
    memcpy(inner_frame, pkt + offset, *inner_len);
    
    /* 7. Learn source MAC -> source VTEP IP mapping */
    if (vxlan_mac_learn(ctx, inner_eth->src_mac, *src_vtep_ip, *vni) != 0) {
        /* Learning failed but decapsulation succeeded - not critical */
        fprintf(stderr, "Warning: MAC learning failed for ");
        for (int i = 0; i < 6; i++) {
            fprintf(stderr, "%02x%s", inner_eth->src_mac[i], i < 5 ? ":" : "");
        }
        fprintf(stderr, "\n");
    }
    
    return 0;
}

/**
 * Helper function: Check if packet is a VXLAN packet
 */
int vxlan_is_vxlan_packet(const uint8_t *packet, size_t len, uint16_t vxlan_port) {
    if (len < sizeof(eth_hdr_t) + sizeof(ip_hdr_t) + sizeof(udp_hdr_t)) {
        return 0;
    }
    
    const eth_hdr_t *eth = (const eth_hdr_t *)packet;
    
    /* Check if IPv4 */
    if (ntohs(eth->ether_type) != 0x0800) {
        return 0;
    }
    
    const ip_hdr_t *ip = (const ip_hdr_t *)(packet + sizeof(eth_hdr_t));
    
    /* Check if UDP */
    if (ip->protocol != 17) {
        return 0;
    }
    
    const udp_hdr_t *udp = (const udp_hdr_t *)(packet + sizeof(eth_hdr_t) + sizeof(ip_hdr_t));
    
    /* Check if VXLAN port */
    if (ntohs(udp->dst_port) != vxlan_port) {
        return 0;
    }
    
    return 1; /* Looks like a VXLAN packet */
}

/**
 * Helper function: Extract VNI from packet without full decapsulation
 */
int vxlan_peek_vni(const uint8_t *packet, size_t len, uint32_t *vni_out) {
    size_t offset = sizeof(eth_hdr_t) + sizeof(ip_hdr_t) + sizeof(udp_hdr_t);
    
    if (len < offset + sizeof(vxlan_hdr_t)) {
        return -1;
    }
    
    const vxlan_hdr_t *vxlan_hdr = (const vxlan_hdr_t *)(packet + offset);
    
    if (!vxlan_validate_header(vxlan_hdr)) {
        return -1;
    }
    
    *vni_out = VXLAN_BYTES_TO_VNI(vxlan_hdr->vni);
    return 0;
}
