
/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : vxlan_utils.c    
 * Purpose     : Utility Functions Implementation
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "../include/vxlan_utils.h"

/**
 * Calculate IP header checksum (RFC 1071)
 */
uint16_t ip_checksum(const void *buf, size_t len) {
    const uint16_t *words = (const uint16_t *)buf;
    uint32_t sum = 0;
    size_t count = len;
    
    /* Sum all 16-bit words */
    while (count > 1) {
        sum += *words++;
        count -= 2;
    }
    
    /* Add left-over byte, if any */
    if (count > 0) {
        sum += *(const uint8_t *)words;
    }
    
    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

/**
 * Calculate UDP checksum (optional for VXLAN, usually 0)
 */
uint16_t udp_checksum(const void *udp_hdr, uint32_t src_ip, uint32_t dst_ip, uint16_t udp_len) {
    /* For VXLAN, UDP checksum is typically 0 (RFC 7348)
     * Full implementation would require pseudo-header calculation
     */
    
    /* Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + protocol(1) + udp_len(2) */
    uint32_t sum = 0;
    
    /* Add source IP */
    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    
    /* Add destination IP */
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;
    
    /* Add protocol (17 for UDP) and length */
    sum += 17; /* UDP protocol */
    sum += udp_len;
    
    /* Add UDP header and data */
    const uint16_t *words = (const uint16_t *)udp_hdr;
    size_t count = udp_len;
    
    while (count > 1) {
        sum += *words++;
        count -= 2;
    }
    
    if (count > 0) {
        sum += *(const uint8_t *)words;
    }
    
    /* Fold to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

/**
 * Hash MAC address for table lookup
 */
uint32_t mac_hash(const uint8_t *mac, uint32_t vni) {
    if (!mac) {
        return 0;
    }
    
    /* Simple hash: XOR all bytes of MAC and VNI */
    uint32_t hash = vni;
    
    for (int i = 0; i < 6; i++) {
        hash ^= (mac[i] << (i * 5)); /* Distribute bits */
    }
    
    /* Mix bits */
    hash ^= (hash >> 16);
    hash ^= (hash >> 8);
    
    return hash;
}

/**
 * Compare two MAC addresses
 */
int mac_compare(const uint8_t *mac1, const uint8_t *mac2) {
    if (!mac1 || !mac2) {
        return -1;
    }
    
    return memcmp(mac1, mac2, 6);
}

/**
 * Copy MAC address
 */
void mac_copy(uint8_t *dst, const uint8_t *src) {
    if (dst && src) {
        memcpy(dst, src, 6);
    }
}

/**
 * Get current time in seconds
 */
time_t get_current_time(void) {
    return time(NULL);
}

/**
 * Print hex dump of data
 */
void hex_dump(const uint8_t *data, size_t len, const char *label) {
    if (!data || len == 0) {
        return;
    }
    
    printf("\n=== %s (%zu bytes) ===\n", label ? label : "Data", len);
    
    for (size_t i = 0; i < len; i += 16) {
        /* Print offset */
        printf("%04zx: ", i);
        
        /* Print hex values */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
            
            if (j == 7) {
                printf(" ");
            }
        }
        
        printf(" |");
        
        /* Print ASCII values */
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        
        printf("|\n");
    }
    
    printf("\n");
}

/**
 * Dump VXLAN packet for debugging
 */
void vxlan_dump_packet(const uint8_t *packet, size_t len, const char *label) {
    if (!packet || len == 0) {
        return;
    }
    
    printf("\n========== VXLAN Packet Dump: %s ==========\n", label ? label : "");
    printf("Total Length: %zu bytes\n\n", len);
    
    if (len < 14) {
        printf("Packet too small for Ethernet header\n");
        hex_dump(packet, len, "Raw Data");
        return;
    }
    
    size_t offset = 0;
    
    /* Outer Ethernet Header */
    printf("--- Outer Ethernet Header ---\n");
    printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    uint16_t eth_type = (packet[12] << 8) | packet[13];
    printf("EtherType: 0x%04x (%s)\n", eth_type, 
           eth_type == 0x0800 ? "IPv4" : "Unknown");
    offset = 14;
    
    if (eth_type != 0x0800 || len < offset + 20) {
        hex_dump(packet, len, "Full Packet");
        return;
    }
    
    /* Outer IP Header */
    printf("\n--- Outer IP Header ---\n");
    uint8_t ver_ihl = packet[offset];
    printf("Version: %u, IHL: %u\n", ver_ihl >> 4, ver_ihl & 0x0F);
    uint16_t ip_len = (packet[offset + 2] << 8) | packet[offset + 3];
    printf("Total Length: %u\n", ip_len);
    printf("Protocol: %u (%s)\n", packet[offset + 9],
           packet[offset + 9] == 17 ? "UDP" : "Other");
    printf("Src IP: %u.%u.%u.%u\n", 
           packet[offset + 12], packet[offset + 13],
           packet[offset + 14], packet[offset + 15]);
    printf("Dst IP: %u.%u.%u.%u\n",
           packet[offset + 16], packet[offset + 17],
           packet[offset + 18], packet[offset + 19]);
    offset += 20;
    
    if (packet[offset - 11] != 17 || len < offset + 8) {
        hex_dump(packet, len, "Full Packet");
        return;
    }
    
    /* Outer UDP Header */
    printf("\n--- Outer UDP Header ---\n");
    uint16_t src_port = (packet[offset] << 8) | packet[offset + 1];
    uint16_t dst_port = (packet[offset + 2] << 8) | packet[offset + 3];
    uint16_t udp_len = (packet[offset + 4] << 8) | packet[offset + 5];
    printf("Src Port: %u\n", src_port);
    printf("Dst Port: %u\n", dst_port);
    printf("Length: %u\n", udp_len);
    offset += 8;
    
    if (len < offset + 8) {
        hex_dump(packet, len, "Full Packet");
        return;
    }
    
    /* VXLAN Header */
    printf("\n--- VXLAN Header ---\n");
    printf("Flags: 0x%02x (I-flag: %s)\n", 
           packet[offset], 
           (packet[offset] & 0x08) ? "SET" : "NOT SET");
    uint32_t vni = (packet[offset + 4] << 16) | 
                   (packet[offset + 5] << 8) | 
                   packet[offset + 6];
    printf("VNI: %u (0x%06x)\n", vni, vni);
    offset += 8;
    
    if (len < offset + 14) {
        hex_dump(packet, len, "Full Packet");
        return;
    }
    
    /* Inner Ethernet Header */
    printf("\n--- Inner Ethernet Header ---\n");
    printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[offset], packet[offset + 1], packet[offset + 2],
           packet[offset + 3], packet[offset + 4], packet[offset + 5]);
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[offset + 6], packet[offset + 7], packet[offset + 8],
           packet[offset + 9], packet[offset + 10], packet[offset + 11]);
    uint16_t inner_type = (packet[offset + 12] << 8) | packet[offset + 13];
    printf("EtherType: 0x%04x\n", inner_type);
    offset += 14;
    
    /* Payload */
    size_t payload_len = len - offset;
    if (payload_len > 0) {
        printf("\n--- Payload (%zu bytes) ---\n", payload_len);
        if (payload_len > 64) {
            hex_dump(packet + offset, 64, "First 64 bytes of payload");
            printf("... (%zu more bytes)\n", payload_len - 64);
        } else {
            hex_dump(packet + offset, payload_len, "Payload");
        }
    }
    
    printf("\n========== End of Packet Dump ==========\n\n");
}
