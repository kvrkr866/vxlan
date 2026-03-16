
/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : vxlan_encap.c  
 * Purpose     : VXLAN Encapsulation Logic
 *                Wraps inner Ethernet frames in VXLAN+UDP+IP+Ethernet headers
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/vxlan.h"
#include "../include/vxlan_utils.h"

/**
 * Calculate UDP source port from inner frame hash
 * Provides entropy for ECMP/load balancing (RFC 7348)
 */
uint16_t vxlan_calc_src_port(const uint8_t *inner_frame, size_t inner_len) {
    if (!inner_frame || inner_len < sizeof(eth_hdr_t)) {
        return VXLAN_SRC_PORT_MIN;
    }
    
    const eth_hdr_t *eth = (const eth_hdr_t *)inner_frame;
    
    /* Hash: XOR of src MAC, dst MAC, and ether type */
    uint32_t hash = 0;
    
    for (int i = 0; i < 6; i++) {
        hash ^= eth->src_mac[i];
        hash ^= eth->dst_mac[i];
    }
    hash ^= ntohs(eth->ether_type);
    
    /* Map to dynamic port range (49152-65535) */
    uint16_t port_range = VXLAN_SRC_PORT_MAX - VXLAN_SRC_PORT_MIN + 1;
    return VXLAN_SRC_PORT_MIN + (hash % port_range);
}

/**
 * Build VXLAN header
 */
static void build_vxlan_header(vxlan_hdr_t *vxlan_hdr, uint32_t vni) {
    memset(vxlan_hdr, 0, sizeof(vxlan_hdr_t));
    
    /* Set I flag (bit 4) to indicate valid VNI */
    vxlan_hdr->flags = VXLAN_I_FLAG;
    
    /* Set 24-bit VNI (network byte order) */
    VXLAN_VNI_TO_BYTES(vni, vxlan_hdr->vni);
    
    /* Reserved fields already zeroed */
}

/**
 * Build outer UDP header
 */
static void build_udp_header(udp_hdr_t *udp_hdr, 
                             uint16_t src_port,
                             uint16_t dst_port,
                             uint16_t payload_len,
                             bool checksum_enabled) {
    udp_hdr->src_port = htons(src_port);
    udp_hdr->dst_port = htons(dst_port);
    udp_hdr->length = htons(sizeof(udp_hdr_t) + payload_len);
    
    /* UDP checksum SHOULD be 0 (RFC 7348) */
    udp_hdr->checksum = 0;
    
    /* Optional: calculate checksum if enabled */
    if (checksum_enabled) {
        /* Note: This requires pseudo-header with src/dst IP 
         * We'll set it to 0 for simplicity, can be calculated later */
        udp_hdr->checksum = 0; /* TODO: Implement if needed */
    }
}

/**
 * Build outer IP header
 */
static void build_ip_header(ip_hdr_t *ip_hdr,
                            uint32_t src_ip,
                            uint32_t dst_ip,
                            uint16_t total_len) {
    memset(ip_hdr, 0, sizeof(ip_hdr_t));
    
    ip_hdr->ver_ihl = 0x45;  /* Version 4, IHL 5 (20 bytes) */
    ip_hdr->tos = 0;         /* Type of Service */
    ip_hdr->total_len = htons(total_len);
    ip_hdr->id = 0;          /* Identification (0 or random) */
    ip_hdr->frag_off = 0;    /* Don't Fragment can be set here */
    ip_hdr->ttl = 64;        /* Time to Live */
    ip_hdr->protocol = 17;   /* UDP */
    ip_hdr->src_ip = src_ip;
    ip_hdr->dst_ip = dst_ip;
    
    /* Calculate IP header checksum */
    ip_hdr->checksum = 0;
    ip_hdr->checksum = ip_checksum(ip_hdr, sizeof(ip_hdr_t));
}

/**
 * Build outer Ethernet header
 */
static void build_eth_header(eth_hdr_t *eth_hdr,
                             const uint8_t *src_mac,
                             const uint8_t *dst_mac) {
    memcpy(eth_hdr->dst_mac, dst_mac, 6);
    memcpy(eth_hdr->src_mac, src_mac, 6);
    eth_hdr->ether_type = htons(0x0800); /* IPv4 */
}

/**
 * Main encapsulation function
 * 
 * Wraps inner Ethernet frame in VXLAN+UDP+IP+Ethernet
 * 
 * RFC 7348 Section 6.1:
 * "When a VLAN-tagged packet is a candidate for VXLAN tunneling, the
 *  encapsulating VTEP SHOULD strip the VLAN tag unless configured otherwise."
 */
int vxlan_encapsulate(vxlan_ctx_t *ctx,
                      const uint8_t *inner_frame,
                      size_t inner_len,
                      uint8_t *outer_packet,
                      size_t *outer_len,
                      uint32_t dst_vtep_ip) {
    
    /* Validate inputs */
    if (!ctx || !inner_frame || !outer_packet || !outer_len) {
        return -1;
    }
    
    if (inner_len < sizeof(eth_hdr_t) || inner_len > ETH_DATA_LEN) {
        return -1;
    }
    
    /* RFC 7348 Section 6.1: Strip VLAN tag if present (unless configured otherwise) */
    uint8_t processed_frame[ETH_DATA_LEN];
    const uint8_t *frame_to_encap = inner_frame;
    size_t frame_len_to_encap = inner_len;
    
    if (ctx->vlan_config.strip_on_encap && vxlan_vlan_is_tagged(inner_frame, inner_len)) {
        uint16_t vlan_id;
        if (vxlan_vlan_get_id(inner_frame, &vlan_id) == 0) {
            printf("Stripping VLAN tag (VLAN %u) before encapsulation per RFC 7348\n", vlan_id);
        }
        
        size_t stripped_len;
        if (vxlan_vlan_strip(inner_frame, inner_len, 
                            processed_frame, &stripped_len) == 0) {
            frame_to_encap = processed_frame;
            frame_len_to_encap = stripped_len;
        } else {
            fprintf(stderr, "Warning: Failed to strip VLAN tag, encapsulating as-is\n");
        }
    }
    
    /* Calculate total outer packet size */
    size_t total_len = sizeof(eth_hdr_t) +      /* Outer Ethernet */
                       sizeof(ip_hdr_t) +        /* Outer IP */
                       sizeof(udp_hdr_t) +       /* Outer UDP */
                       sizeof(vxlan_hdr_t) +     /* VXLAN header */
                       frame_len_to_encap;       /* Inner frame (possibly stripped) */
    
    if (total_len > 9000) { /* Jumbo frame check */
        return -1;
    }
    
    /* Build packet from inside out */
    uint8_t *pkt = outer_packet;
    size_t offset = 0;
    
    /* 1. Outer Ethernet Header */
    eth_hdr_t *outer_eth = (eth_hdr_t *)(pkt + offset);
    /* Note: In real implementation, dst_mac would be resolved via ARP
     * or from next-hop router. For now, we'll use broadcast or default */
    uint8_t dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; /* Broadcast for now */
    build_eth_header(outer_eth, ctx->vtep.local_mac, dst_mac);
    offset += sizeof(eth_hdr_t);
    
    /* 2. Outer IP Header */
    ip_hdr_t *outer_ip = (ip_hdr_t *)(pkt + offset);
    uint16_t ip_total_len = sizeof(ip_hdr_t) + sizeof(udp_hdr_t) + 
                            sizeof(vxlan_hdr_t) + frame_len_to_encap;
    build_ip_header(outer_ip, ctx->vtep.local_ip, dst_vtep_ip, ip_total_len);
    offset += sizeof(ip_hdr_t);
    
    /* 3. Outer UDP Header */
    udp_hdr_t *outer_udp = (udp_hdr_t *)(pkt + offset);
    uint16_t src_port = vxlan_calc_src_port(frame_to_encap, frame_len_to_encap);
    uint16_t udp_payload_len = sizeof(vxlan_hdr_t) + frame_len_to_encap;
    build_udp_header(outer_udp, src_port, ctx->vtep.udp_port, 
                     udp_payload_len, ctx->vtep.checksum_enabled);
    offset += sizeof(udp_hdr_t);
    
    /* 4. VXLAN Header */
    vxlan_hdr_t *vxlan_hdr = (vxlan_hdr_t *)(pkt + offset);
    build_vxlan_header(vxlan_hdr, ctx->vtep.vni);
    offset += sizeof(vxlan_hdr_t);
    
    /* 5. Inner Ethernet Frame (payload - possibly stripped of VLAN) */
    memcpy(pkt + offset, frame_to_encap, frame_len_to_encap);
    offset += frame_len_to_encap;
    
    *outer_len = offset;
    
    return 0;
}

/**
 * Validate VXLAN header
 */
bool vxlan_validate_header(const vxlan_hdr_t *vxlan_hdr) {
    if (!vxlan_hdr) {
        return false;
    }
    
    /* Check I flag is set (bit 4) */
    if ((vxlan_hdr->flags & VXLAN_I_FLAG) == 0) {
        return false;
    }
    
    /* Reserved bits should be 0 (but we ignore them per RFC) */
    
    return true;
}
