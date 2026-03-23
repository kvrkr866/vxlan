/*****************************************************************************
 * Project     : EVPN Protocol Implementation (RFC 8365)
 * Description : Complete Demo - All Layer 3 Features
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : l3_features_demo.c  
 * Purpose     : Demonstrates Type 5 routes, MAC mobility, ARP suppression,
 *               and route policies
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/evpn.h"
#include "../include/evpn_routes.h"

#define ANSI_GREEN  "\033[32m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_BLUE   "\033[34m"
#define ANSI_CYAN   "\033[36m"
#define ANSI_RESET  "\033[0m"

void print_separator() {
    printf("\n═══════════════════════════════════════════════════════════════\n");
}

int main() {
    printf("\n" ANSI_BLUE);
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║          EVPN Complete Demo                           ║\n");
    printf("║    Layer 3 Support & Advanced Features                       ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf(ANSI_RESET);
    
    // Initialize
    evpn_ctx_t evpn;
    evpn_init(&evpn, NULL, 65000, inet_addr("10.0.0.1"));
    print_separator();
    
    // FEATURE 1: Type 5 Routes (IP Prefix)
    printf(ANSI_YELLOW "Feature 1: Type 5 Routes (IP Prefix)" ANSI_RESET "\n");
    printf("─────────────────────────────────────────────\n\n");
    
    printf("Use case: Inter-subnet routing\n");
    printf("Scenario: Route 192.168.1.0/24 to remote subnet\n\n");
    
    uint32_t prefix = inet_addr("192.168.1.0");
    uint32_t gw = inet_addr("192.168.1.1");
    evpn_advertise_ip_prefix(&evpn, prefix, 24, gw, 1000);
    
    printf("\n" ANSI_GREEN "✓" ANSI_RESET " Type 5 route advertised\n");
    printf("  Benefit: Inter-subnet routing without traditional IP routing\n");
    
    print_separator();
    
    // FEATURE 2: MAC Mobility
    printf(ANSI_YELLOW "Feature 2: MAC Mobility" ANSI_RESET "\n");
    printf("─────────────────────────────────────────────\n\n");
    
    printf("Use case: VM migration between hosts\n");
    printf("Scenario: MAC moves from VTEP1 to VTEP2\n\n");
    
    uint8_t mac[6] = {0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc};
    uint32_t vtep1 = inet_addr("10.0.0.1");
    uint32_t vtep2 = inet_addr("10.0.0.2");
    
    // Initial location
    evpn_detect_mac_move(&evpn, mac, 1000, vtep1, NULL);
    
    // MAC moves
    uint32_t old_vtep;
    if (evpn_detect_mac_move(&evpn, mac, 1000, vtep2, &old_vtep)) {
        evpn_handle_mac_move(&evpn, mac, 1000, old_vtep, vtep2);
    }
    
    printf(ANSI_GREEN "✓" ANSI_RESET " MAC mobility detected and handled\n");
    printf("  Benefit: Seamless VM migration, loop prevention\n");
    
    print_separator();
    
    // FEATURE 3: ARP Suppression
    printf(ANSI_YELLOW "Feature 3: ARP Suppression" ANSI_RESET "\n");
    printf("─────────────────────────────────────────────\n\n");
    
    printf("Use case: Reduce ARP flooding\n");
    printf("Scenario: VTEP answers ARP locally\n\n");
    
    evpn_enable_arp_suppression(&evpn, 1000);
    
    // Populate ARP cache
    uint8_t mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint32_t ip1 = inet_addr("192.168.1.10");
    evpn_arp_cache_add(&evpn, ip1, mac1, 1000);
    
    // Handle ARP request
    uint8_t reply_mac[6];
    if (evpn_handle_arp_request(&evpn, ip1, 1000, reply_mac)) {
        printf("      ✓ ARP request suppressed (answered locally)\n");
    }
    
    uint64_t received, suppressed, entries;
    evpn_get_arp_stats(&evpn, 1000, &received, &suppressed, &entries);
    
    printf("\n" ANSI_GREEN "✓" ANSI_RESET " ARP suppression working\n");
    printf("  Stats: %lu requests, %lu suppressed, %lu cache entries\n",
           received, suppressed, entries);
    printf("  Benefit: %lu%% reduction in ARP flooding\n",
           received > 0 ? (suppressed * 100 / received) : 0);
    
    print_separator();
    
    // FEATURE 4: Route Policies
    printf(ANSI_YELLOW "Feature 4: Route Policies" ANSI_RESET "\n");
    printf("─────────────────────────────────────────────\n\n");
    
    printf("Use case: Filtering routes\n");
    printf("Scenario: Control route import/export\n\n");
    
    evpn_create_policy(&evpn, "permit-vni-1000", EVPN_POLICY_PERMIT);
    evpn_create_policy(&evpn, "deny-vni-2000", EVPN_POLICY_DENY);
    
    printf("\n" ANSI_GREEN "✓" ANSI_RESET " Route policies created\n");
    printf("  Benefit: Fine-grained control over route distribution\n");
    
    print_separator();
    
    // Summary
    printf(ANSI_BLUE);
    printf("╔═══════════════════════════════════════════════════════════════════╗\n");
    printf("║              All Layer3 FEATURES COMPLETE                         ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════╝\n");
    printf(ANSI_RESET);
    
    printf("\n" ANSI_GREEN "KEY ACHIEVEMENTS:" ANSI_RESET "\n");
    printf("  ✓ Type 5 routes for inter-subnet routing\n");
    printf("  ✓ MAC mobility with sequence numbers\n");
    printf("  ✓ ARP suppression reduces flooding\n");
    printf("  ✓ Route policies for filtering\n");
    
    printf("\n" ANSI_CYAN "REAL-WORLD IMPACT:" ANSI_RESET "\n");
    printf("  • Complete Layer 2 + Layer 3 EVPN\n");
    printf("  • VM migration support\n");
    printf("  • Reduced overlay traffic\n");
    printf("  • Policy-based routing\n");
    
    print_separator();
    evpn_cleanup(&evpn);
    printf(ANSI_GREEN "\n✓ L3 features  Demo Finished!\n" ANSI_RESET);
    
    return 0;
}
