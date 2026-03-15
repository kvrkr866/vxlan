
/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : vxlan_init.c  
 * Purpose     : VXLAN Context Initialization and Cleanup functions
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h> // Header where struct ifreq is defined
#include <sys/ioctl.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../include/vxlan.h"
#include "../include/vxlan_utils.h"

/**
 * Get local MAC address for a given interface
 */
static int get_local_mac(const char *ifname, uint8_t *mac) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(sockfd);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sockfd);
    
    return 0;
}

/**
 * Initialize VXLAN context
 */
int vxlan_init(vxlan_ctx_t *ctx, uint32_t local_ip, uint32_t vni) {
    if (!ctx) {
        return -1;
    }
    
    /* Validate VNI */
    if (vni > VXLAN_VNI_MAX) {
        fprintf(stderr, "Invalid VNI: %u (max is %u)\n", vni, VXLAN_VNI_MAX);
        return -1;
    }
    
    /* Clear context */
    memset(ctx, 0, sizeof(vxlan_ctx_t));
    
    /* Initialize VTEP configuration */
    ctx->vtep.local_ip = local_ip;
    ctx->vtep.vni = vni;
    ctx->vtep.udp_port = VXLAN_UDP_PORT;
    ctx->vtep.checksum_enabled = false; /* RFC 7348: checksum SHOULD be 0 */
    ctx->vtep.multicast_ip = 0; /* Not configured by default */
    
    /* Get local MAC address (try eth0 first, then any available interface) */
    if (get_local_mac("eth0", ctx->vtep.local_mac) != 0) {
        /* Try other common interface names */
        if (get_local_mac("ens33", ctx->vtep.local_mac) != 0 &&
            get_local_mac("ens160", ctx->vtep.local_mac) != 0 &&
            get_local_mac("enp0s3", ctx->vtep.local_mac) != 0) {
            /* Use a default MAC if we can't get the real one */
            fprintf(stderr, "Warning: Could not get local MAC, using default\n");
            uint8_t default_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
            memcpy(ctx->vtep.local_mac, default_mac, 6);
        }
    }
    
    /* Initialize MAC learning table */
    for (int i = 0; i < MAC_TABLE_SIZE; i++) {
        ctx->mac_table[i] = NULL;
    }
    
    /* Initialize mutex for thread-safe MAC table access */
    if (pthread_mutex_init(&ctx->mac_lock, NULL) != 0) {
        perror("pthread_mutex_init");
        return -1;
    }
    
    /* Create raw socket for packet I/O (optional - for actual network I/O) */
    ctx->vtep.sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (ctx->vtep.sockfd < 0) {
        fprintf(stderr, "Warning: Could not create raw socket (need root): %m\n");
        /* Not critical - can still do encap/decap without actual I/O */
        ctx->vtep.sockfd = -1;
    }
    
    /* Set running flag */
    ctx->running = true;
    
    /* Print configuration */
    printf("VXLAN VTEP Initialized:\n");
    printf("  Local IP: %s\n", inet_ntoa(*(struct in_addr*)&local_ip));
    printf("  Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ctx->vtep.local_mac[0], ctx->vtep.local_mac[1],
           ctx->vtep.local_mac[2], ctx->vtep.local_mac[3],
           ctx->vtep.local_mac[4], ctx->vtep.local_mac[5]);
    printf("  VNI: %u\n", vni);
    printf("  UDP Port: %u\n", ctx->vtep.udp_port);
    printf("  Checksum: %s\n", ctx->vtep.checksum_enabled ? "Enabled" : "Disabled");
    
    return 0;
}

/**
 * Cleanup VXLAN context
 */
void vxlan_cleanup(vxlan_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    
    /* Stop any running threads */
    ctx->running = false;
    
    /* Close socket */
    if (ctx->vtep.sockfd >= 0) {
        close(ctx->vtep.sockfd);
        ctx->vtep.sockfd = -1;
    }
    
    /* Clear MAC learning table */
    pthread_mutex_lock(&ctx->mac_lock);
    
    for (int i = 0; i < MAC_TABLE_SIZE; i++) {
        mac_entry_t *entry = ctx->mac_table[i];
        while (entry != NULL) {
            mac_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        ctx->mac_table[i] = NULL;
    }
    
    pthread_mutex_unlock(&ctx->mac_lock);
    
    /* Destroy mutex */
    pthread_mutex_destroy(&ctx->mac_lock);
    
    printf("VXLAN VTEP Cleaned up\n");
}

/**
 * Get VXLAN statistics
 */
void vxlan_get_stats(vxlan_ctx_t *ctx, vxlan_stats_t *stats) {
    if (!ctx || !stats) {
        return;
    }
    
    memset(stats, 0, sizeof(vxlan_stats_t));
    
    /* Count MAC table entries */
    pthread_mutex_lock(&ctx->mac_lock);
    
    for (int i = 0; i < MAC_TABLE_SIZE; i++) {
        mac_entry_t *entry = ctx->mac_table[i];
        while (entry != NULL) {
            stats->mac_learning_count++;
            entry = entry->next;
        }
    }
    
    pthread_mutex_unlock(&ctx->mac_lock);
    
    /* Note: TX/RX packet/byte counters would need to be incremented
     * in the actual send/receive functions when integrated with real I/O */
}

/**
 * Set VTEP multicast group IP (for BUM traffic)
 */
int vxlan_set_multicast_group(vxlan_ctx_t *ctx, uint32_t mcast_ip) {
    if (!ctx) {
        return -1;
    }
    
    /* Validate multicast IP (224.0.0.0 to 239.255.255.255) */
    uint8_t first_octet = (mcast_ip & 0xFF);
    if (first_octet < 224 || first_octet > 239) {
        fprintf(stderr, "Invalid multicast IP: not in range 224.0.0.0-239.255.255.255\n");
        return -1;
    }
    
    ctx->vtep.multicast_ip = mcast_ip;
    
    printf("Multicast group set to: %s\n", inet_ntoa(*(struct in_addr*)&mcast_ip));
    
    return 0;
}

/**
 * Set UDP port (for compatibility with non-standard implementations)
 */
int vxlan_set_udp_port(vxlan_ctx_t *ctx, uint16_t port) {
    if (!ctx) {
        return -1;
    }
    
    if (port == 0) {
        fprintf(stderr, "Invalid UDP port: 0\n");
        return -1;
    }
    
    ctx->vtep.udp_port = port;
    
    printf("UDP port set to: %u\n", port);
    
    return 0;
}

/**
 * Enable/disable UDP checksum calculation
 */
void vxlan_set_checksum(vxlan_ctx_t *ctx, bool enabled) {
    if (!ctx) {
        return;
    }
    
    ctx->vtep.checksum_enabled = enabled;
    
    printf("UDP checksum: %s\n", enabled ? "Enabled" : "Disabled");
}
