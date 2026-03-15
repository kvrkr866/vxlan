/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : vxlan_utils.h  
 * Purpose     : VXLAN Utility functions
 *****************************************************************************/

#ifndef VXLAN_UTILS_H
#define VXLAN_UTILS_H

#include <stdint.h>
#include <stddef.h>

/**
 * Calculate IP header checksum (RFC 1071)
 * 
 * @param buf   IP header buffer
 * @param len   Header length in bytes
 * @return      Checksum value
 */
uint16_t ip_checksum(const void *buf, size_t len);

/**
 * Calculate UDP checksum
 * 
 * @param udp_hdr   UDP header
 * @param src_ip    Source IP (network byte order)
 * @param dst_ip    Destination IP (network byte order)
 * @param udp_len   UDP length (host byte order)
 * @return          Checksum value
 */
uint16_t udp_checksum(const void *udp_hdr, uint32_t src_ip, uint32_t dst_ip, uint16_t udp_len);

/**
 * Hash MAC address for table lookup
 * 
 * @param mac   MAC address (6 bytes)
 * @param vni   VNI
 * @return      Hash value
 */
uint32_t mac_hash(const uint8_t *mac, uint32_t vni);

/**
 * Compare MAC addresses
 * 
 * @param mac1  First MAC address
 * @param mac2  Second MAC address
 * @return      0 if equal, non-zero otherwise
 */
int mac_compare(const uint8_t *mac1, const uint8_t *mac2);

/**
 * Copy MAC address
 * 
 * @param dst   Destination
 * @param src   Source
 */
void mac_copy(uint8_t *dst, const uint8_t *src);

/**
 * Get current time in seconds
 * 
 * @return  Current time
 */
time_t get_current_time(void);

/**
 * Print hex dump of data
 * 
 * @param data  Data buffer
 * @param len   Length
 * @param label Description
 */
void hex_dump(const uint8_t *data, size_t len, const char *label);

#endif /* VXLAN_UTILS_H */
