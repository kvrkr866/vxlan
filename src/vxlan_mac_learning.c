
/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : vxlan_mac_learning.c  
 * Purpose     : Implements a hash table for MAC address to VTEP IP mapping
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include "../include/vxlan.h"
#include "../include/vxlan_utils.h"

/**
 * Learn a MAC address mapping
 * 
 * Associates MAC address with remote VTEP IP for a given VNI
 */
int vxlan_mac_learn(vxlan_ctx_t *ctx, const uint8_t *mac, uint32_t vtep_ip, uint32_t vni) {
    if (!ctx || !mac) {
        return -1;
    }
    
    pthread_mutex_lock(&ctx->mac_lock);
    
    /* Calculate hash */
    uint32_t hash = mac_hash(mac, vni) % MAC_TABLE_SIZE;
    
    /* Check if entry already exists */
    mac_entry_t *entry = ctx->mac_table[hash];
    while (entry != NULL) {
        if (mac_compare(entry->mac, mac) == 0 && entry->vni == vni) {
            /* Update existing entry */
            entry->vtep_ip = vtep_ip;
            entry->timestamp = get_current_time();
            pthread_mutex_unlock(&ctx->mac_lock);
            return 0;
        }
        entry = entry->next;
    }
    
    /* Create new entry */
    mac_entry_t *new_entry = (mac_entry_t *)malloc(sizeof(mac_entry_t));
    if (!new_entry) {
        pthread_mutex_unlock(&ctx->mac_lock);
        return -1;
    }
    
    mac_copy(new_entry->mac, mac);
    new_entry->vtep_ip = vtep_ip;
    new_entry->vni = vni;
    new_entry->timestamp = get_current_time();
    
    /* Insert at head of chain */
    new_entry->next = ctx->mac_table[hash];
    ctx->mac_table[hash] = new_entry;
    
    pthread_mutex_unlock(&ctx->mac_lock);
    
    char mac_str[18];
    MAC_TO_STR(mac, mac_str);
    printf("MAC learned: %s -> VTEP %s (VNI %u)\n", 
           mac_str, inet_ntoa(*(struct in_addr*)&vtep_ip), vni);
    
    return 0;
}

/**
 * Lookup MAC address in learning table
 */
int vxlan_mac_lookup(vxlan_ctx_t *ctx, const uint8_t *mac, uint32_t vni, uint32_t *vtep_ip) {
    if (!ctx || !mac || !vtep_ip) {
        return -1;
    }
    
    pthread_mutex_lock(&ctx->mac_lock);
    
    uint32_t hash = mac_hash(mac, vni) % MAC_TABLE_SIZE;
    
    mac_entry_t *entry = ctx->mac_table[hash];
    while (entry != NULL) {
        if (mac_compare(entry->mac, mac) == 0 && entry->vni == vni) {
            *vtep_ip = entry->vtep_ip;
            pthread_mutex_unlock(&ctx->mac_lock);
            return 0; /* Found */
        }
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&ctx->mac_lock);
    return -1; /* Not found */
}

/**
 * Remove a MAC entry from the table
 */
static int vxlan_mac_remove(vxlan_ctx_t *ctx, const uint8_t *mac, uint32_t vni) {
    if (!ctx || !mac) {
        return -1;
    }
    
    uint32_t hash = mac_hash(mac, vni) % MAC_TABLE_SIZE;
    
    mac_entry_t *entry = ctx->mac_table[hash];
    mac_entry_t *prev = NULL;
    
    while (entry != NULL) {
        if (mac_compare(entry->mac, mac) == 0 && entry->vni == vni) {
            /* Found - remove it */
            if (prev == NULL) {
                /* Head of chain */
                ctx->mac_table[hash] = entry->next;
            } else {
                prev->next = entry->next;
            }
            free(entry);
            return 0;
        }
        prev = entry;
        entry = entry->next;
    }
    
    return -1; /* Not found */
}

/**
 * Age out old MAC entries
 * 
 * Removes entries older than MAC_AGING_TIME seconds
 */
int vxlan_mac_age(vxlan_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }
    
    int aged_count = 0;
    time_t current_time = get_current_time();
    
    pthread_mutex_lock(&ctx->mac_lock);
    
    for (int i = 0; i < MAC_TABLE_SIZE; i++) {
        mac_entry_t *entry = ctx->mac_table[i];
        mac_entry_t *prev = NULL;
        
        while (entry != NULL) {
            mac_entry_t *next = entry->next;
            
            /* Check if entry has aged out */
            if ((current_time - entry->timestamp) > MAC_AGING_TIME) {
                /* Remove this entry */
                if (prev == NULL) {
                    ctx->mac_table[i] = next;
                } else {
                    prev->next = next;
                }
                
                char mac_str[18];
                MAC_TO_STR(entry->mac, mac_str);
                printf("MAC aged out: %s (VNI %u)\n", mac_str, entry->vni);
                
                free(entry);
                aged_count++;
            } else {
                prev = entry;
            }
            
            entry = next;
        }
    }
    
    pthread_mutex_unlock(&ctx->mac_lock);
    
    return aged_count;
}

/**
 * Clear all MAC entries
 */
void vxlan_mac_clear(vxlan_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    
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
    
    printf("MAC table cleared\n");
}

/**
 * Get MAC table statistics
 */
int vxlan_mac_count(vxlan_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }
    
    int count = 0;
    
    pthread_mutex_lock(&ctx->mac_lock);
    
    for (int i = 0; i < MAC_TABLE_SIZE; i++) {
        mac_entry_t *entry = ctx->mac_table[i];
        while (entry != NULL) {
            count++;
            entry = entry->next;
        }
    }
    
    pthread_mutex_unlock(&ctx->mac_lock);
    
    return count;
}

/**
 * Dump MAC table to stdout (for debugging)
 */
void vxlan_mac_dump(vxlan_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    
    printf("\n=== MAC Learning Table ===\n");
    printf("%-20s %-15s %-10s %-20s\n", "MAC Address", "VTEP IP", "VNI", "Age (seconds)");
    printf("-------------------------------------------------------------------\n");
    
    pthread_mutex_lock(&ctx->mac_lock);
    
    time_t current_time = get_current_time();
    int count = 0;
    
    for (int i = 0; i < MAC_TABLE_SIZE; i++) {
        mac_entry_t *entry = ctx->mac_table[i];
        while (entry != NULL) {
            char mac_str[18];
            char ip_str[16];
            
            MAC_TO_STR(entry->mac, mac_str);
            IP_TO_STR(entry->vtep_ip, ip_str);
            
            time_t age = current_time - entry->timestamp;
            
            printf("%-20s %-15s %-10u %-20ld\n", 
                   mac_str, ip_str, entry->vni, age);
            
            count++;
            entry = entry->next;
        }
    }
    
    pthread_mutex_unlock(&ctx->mac_lock);
    
    printf("-------------------------------------------------------------------\n");
    printf("Total entries: %d\n\n", count);
}

/**
 * Aging thread function
 * 
 * Periodically removes old MAC entries
 */
void* vxlan_mac_aging_thread(void *arg) {
    vxlan_ctx_t *ctx = (vxlan_ctx_t *)arg;
    
    while (ctx->running) {
        sleep(30); /* Check every 30 seconds */
        
        int aged = vxlan_mac_age(ctx);
        if (aged > 0) {
            printf("Aged out %d MAC entries\n", aged);
        }
    }
    
    return NULL;
}
