 
/*****************************************************************************
 * Project     : VXLAN Protocol Implementation (RFC 7348)
 * Description : Part of minimal implementation of VXLAN (RFC-7348)
 *                Virtual eXtensible Local Area Network (VXLAN)
 *                encapsulation and decapsulation 
 *                implementation with minimal testing 
 * Author      : RK (kvrkr866@gmail.com)
 * File name   : test_vxlan.c  
 * Purpose     : VXLAN unit tets - minimal test suite for VXLAN implementation
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>
#include "../include/vxlan.h"

#define ANSI_GREEN  "\033[32m"
#define ANSI_RED    "\033[31m"
#define ANSI_RESET  "\033[0m"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    printf("\n" ANSI_RESET "Testing: %s ... ", name); \
    fflush(stdout);

#define PASS() \
    do { \
        printf(ANSI_GREEN "PASS" ANSI_RESET "\n"); \
        tests_passed++; \
    } while(0)

#define FAIL(msg) \
    do { \
        printf(ANSI_RED "FAIL" ANSI_RESET ": %s\n", msg); \
        tests_failed++; \
    } while(0)

#define ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            FAIL(msg); \
            return; \
        } \
    } while(0)

/* Test 1: Initialization */
void test_init() {
    TEST("VXLAN Initialization");
    
    vxlan_ctx_t ctx;
    uint32_t local_ip = inet_addr("192.168.1.100");
    uint32_t vni = 100;
    
    int ret = vxlan_init(&ctx, local_ip, vni);
    ASSERT(ret == 0, "vxlan_init failed");
    ASSERT(ctx.vtep.local_ip == local_ip, "Local IP not set correctly");
    ASSERT(ctx.vtep.vni == vni, "VNI not set correctly");
    ASSERT(ctx.vtep.udp_port == VXLAN_UDP_PORT, "UDP port not default");
    
    vxlan_cleanup(&ctx);
    PASS();
}

/* Test 2: Invalid VNI */
void test_invalid_vni() {
    TEST("Invalid VNI Rejection");
    
    vxlan_ctx_t ctx;
    uint32_t local_ip = inet_addr("192.168.1.100");
    uint32_t invalid_vni = VXLAN_VNI_MAX + 1;
    
    int ret = vxlan_init(&ctx, local_ip, invalid_vni);
    ASSERT(ret != 0, "Should reject invalid VNI");
    
    PASS();
}

/* Test 3: VXLAN Header Construction */
void test_vxlan_header() {
    TEST("VXLAN Header Construction");
    
    vxlan_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    
    /* Manually construct header */
    hdr.flags = VXLAN_I_FLAG;
    uint32_t vni = 12345;
    VXLAN_VNI_TO_BYTES(vni, hdr.vni);
    
    /* Validate */
    ASSERT(vxlan_validate_header(&hdr), "Valid header rejected");
    ASSERT((hdr.flags & VXLAN_I_FLAG) != 0, "I-flag not set");
    
    uint32_t extracted_vni = VXLAN_BYTES_TO_VNI(hdr.vni);
    ASSERT(extracted_vni == vni, "VNI not correctly encoded/decoded");
    
    /* Test invalid header (I-flag not set) */
    hdr.flags = 0;
    ASSERT(!vxlan_validate_header(&hdr), "Invalid header accepted");
    
    PASS();
}

/* Test 4: Basic Encapsulation */
void test_encapsulation() {
    TEST("Basic Encapsulation");
    
    vxlan_ctx_t ctx;
    vxlan_init(&ctx, inet_addr("192.168.1.100"), 100);
    
    /* Create inner frame */
    uint8_t inner_frame[128];
    eth_hdr_t *eth = (eth_hdr_t *)inner_frame;
    
    uint8_t src_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t dst_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    
    memcpy(eth->src_mac, src_mac, 6);
    memcpy(eth->dst_mac, dst_mac, 6);
    eth->ether_type = htons(0x0800);
    
    const char *payload = "Test";
    memcpy(inner_frame + sizeof(eth_hdr_t), payload, strlen(payload));
    size_t inner_len = sizeof(eth_hdr_t) + strlen(payload);
    
    /* Encapsulate */
    uint8_t outer_packet[2048];
    size_t outer_len;
    uint32_t dst_vtep = inet_addr("192.168.1.200");
    
    int ret = vxlan_encapsulate(&ctx, inner_frame, inner_len,
                                 outer_packet, &outer_len, dst_vtep);
    
    ASSERT(ret == 0, "Encapsulation failed");
    ASSERT(outer_len > inner_len, "Outer packet not larger than inner");
    
    /* Verify VXLAN header is present */
    size_t vxlan_offset = sizeof(eth_hdr_t) + sizeof(ip_hdr_t) + sizeof(udp_hdr_t);
    vxlan_hdr_t *vxlan_hdr = (vxlan_hdr_t *)(outer_packet + vxlan_offset);
    
    ASSERT(vxlan_validate_header(vxlan_hdr), "VXLAN header invalid");
    
    uint32_t vni = VXLAN_BYTES_TO_VNI(vxlan_hdr->vni);
    ASSERT(vni == 100, "VNI mismatch in encapsulated packet");
    
    vxlan_cleanup(&ctx);
    PASS();
}

/* Test 5: Encapsulation + Decapsulation Round Trip */
void test_roundtrip() {
    TEST("Encapsulation/Decapsulation Round Trip");
    
    vxlan_ctx_t ctx;
    vxlan_init(&ctx, inet_addr("192.168.1.100"), 100);
    
    /* Create inner frame */
    uint8_t inner_frame[128];
    eth_hdr_t *eth = (eth_hdr_t *)inner_frame;
    
    uint8_t src_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t dst_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    
    memcpy(eth->src_mac, src_mac, 6);
    memcpy(eth->dst_mac, dst_mac, 6);
    eth->ether_type = htons(0x0800);
    
    const char *payload = "Hello VXLAN!";
    memcpy(inner_frame + sizeof(eth_hdr_t), payload, strlen(payload));
    size_t inner_len = sizeof(eth_hdr_t) + strlen(payload);
    
    /* Encapsulate */
    uint8_t outer_packet[2048];
    size_t outer_len;
    uint32_t dst_vtep = inet_addr("192.168.1.200");
    
    int ret = vxlan_encapsulate(&ctx, inner_frame, inner_len,
                                 outer_packet, &outer_len, dst_vtep);
    ASSERT(ret == 0, "Encapsulation failed");
    
    /* Decapsulate */
    uint8_t decap_frame[2048];
    size_t decap_len;
    uint32_t src_vtep;
    uint32_t vni;
    
    ret = vxlan_decapsulate(&ctx, outer_packet, outer_len,
                            decap_frame, &decap_len, &src_vtep, &vni);
    
    ASSERT(ret == 0, "Decapsulation failed");
    ASSERT(decap_len == inner_len, "Decapsulated length mismatch");
    ASSERT(memcmp(inner_frame, decap_frame, inner_len) == 0, "Frame integrity check failed");
    ASSERT(vni == 100, "VNI mismatch");
    
    vxlan_cleanup(&ctx);
    PASS();
}

/* Test 6: MAC Learning */
void test_mac_learning() {
    TEST("MAC Address Learning");
    
    vxlan_ctx_t ctx;
    vxlan_init(&ctx, inet_addr("192.168.1.100"), 100);
    
    uint8_t mac1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t mac2[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint32_t vtep1 = inet_addr("192.168.1.201");
    uint32_t vtep2 = inet_addr("192.168.1.202");
    
    /* Learn MAC addresses */
    int ret = vxlan_mac_learn(&ctx, mac1, vtep1, 100);
    ASSERT(ret == 0, "MAC learning failed");
    
    ret = vxlan_mac_learn(&ctx, mac2, vtep2, 100);
    ASSERT(ret == 0, "MAC learning failed");
    
    /* Lookup */
    uint32_t found_vtep;
    ret = vxlan_mac_lookup(&ctx, mac1, 100, &found_vtep);
    ASSERT(ret == 0, "MAC lookup failed");
    ASSERT(found_vtep == vtep1, "VTEP IP mismatch");
    
    ret = vxlan_mac_lookup(&ctx, mac2, 100, &found_vtep);
    ASSERT(ret == 0, "MAC lookup failed");
    ASSERT(found_vtep == vtep2, "VTEP IP mismatch");
    
    /* Test non-existent MAC */
    uint8_t mac3[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ret = vxlan_mac_lookup(&ctx, mac3, 100, &found_vtep);
    ASSERT(ret != 0, "Found non-existent MAC");
    
    vxlan_cleanup(&ctx);
    PASS();
}

/* Test 7: Multi-VNI Support */
void test_multi_vni() {
    TEST("Multi-VNI Isolation");
    
    vxlan_ctx_t ctx;
    vxlan_init(&ctx, inet_addr("192.168.1.100"), 0); /* Multi-VNI mode */
    
    uint8_t mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint32_t vtep1 = inet_addr("192.168.1.201");
    uint32_t vtep2 = inet_addr("192.168.1.202");
    
    /* Same MAC in different VNIs */
    vxlan_mac_learn(&ctx, mac, vtep1, 100);
    vxlan_mac_learn(&ctx, mac, vtep2, 200);
    
    /* Lookup should return different VTEPs for different VNIs */
    uint32_t found_vtep;
    vxlan_mac_lookup(&ctx, mac, 100, &found_vtep);
    ASSERT(found_vtep == vtep1, "VNI 100 VTEP mismatch");
    
    vxlan_mac_lookup(&ctx, mac, 200, &found_vtep);
    ASSERT(found_vtep == vtep2, "VNI 200 VTEP mismatch");
    
    vxlan_cleanup(&ctx);
    PASS();
}

/* Test 8: Source Port Hashing */
void test_src_port_hash() {
    TEST("UDP Source Port Hashing (ECMP)");
    
    uint8_t frame1[64], frame2[64];
    eth_hdr_t *eth1 = (eth_hdr_t *)frame1;
    eth_hdr_t *eth2 = (eth_hdr_t *)frame2;
    
    /* Different frames */
    uint8_t mac1[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t mac2[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    
    memcpy(eth1->src_mac, mac1, 6);
    memcpy(eth1->dst_mac, mac2, 6);
    eth1->ether_type = htons(0x0800);
    
    memcpy(eth2->src_mac, mac2, 6);
    memcpy(eth2->dst_mac, mac1, 6);
    eth2->ether_type = htons(0x0800);
    
    uint16_t port1 = vxlan_calc_src_port(frame1, sizeof(frame1));
    uint16_t port2 = vxlan_calc_src_port(frame2, sizeof(frame2));
    
    /* Ports should be in valid range */
    ASSERT(port1 >= VXLAN_SRC_PORT_MIN && port1 <= VXLAN_SRC_PORT_MAX,
           "Port out of range");
    ASSERT(port2 >= VXLAN_SRC_PORT_MIN && port2 <= VXLAN_SRC_PORT_MAX,
           "Port out of range");
    
    /* Different frames should (likely) have different ports */
    ASSERT(port1 != port2, "Hash collision (unlikely but possible)");
    
    PASS();
}

/* Test 9: Checksum Calculation */
void test_checksum() {
    TEST("IP Checksum Calculation");
    
    /* Known test vector */
    uint8_t ip_header[20] = {
        0x45, 0x00, 0x00, 0x3c, /* Ver/IHL, TOS, Total Len */
        0x1c, 0x46, 0x40, 0x00, /* ID, Flags/Frag */
        0x40, 0x06, 0x00, 0x00, /* TTL, Proto, Checksum (0) */
        0xac, 0x10, 0x0a, 0x63, /* Src IP: 172.16.10.99 */
        0xac, 0x10, 0x0a, 0x0c  /* Dst IP: 172.16.10.12 */
    };
    
    uint16_t checksum = ip_checksum(ip_header, 20);
    
    /* Expected checksum for this header: 0xb1e6 */
    ASSERT(checksum == 0xb1e6, "IP checksum calculation incorrect");
    
    PASS();
}

/* Test 10: MAC Table Capacity */
void test_mac_capacity() {
    TEST("MAC Table Large Capacity");
    
    vxlan_ctx_t ctx;
    vxlan_init(&ctx, inet_addr("192.168.1.100"), 100);
    
    /* Add many MAC entries */
    int count = 100;
    for (int i = 0; i < count; i++) {
        uint8_t mac[6] = {0x00, 0x11, 0x22, (i >> 8) & 0xFF, i & 0xFF, 0x00};
        uint32_t vtep = inet_addr("192.168.1.200") + i;
        vxlan_mac_learn(&ctx, mac, vtep, 100);
    }
    
    /* Verify all are present */
    int found = vxlan_mac_count(&ctx);
    ASSERT(found == count, "Not all MACs were learned");
    
    vxlan_cleanup(&ctx);
    PASS();
}

int main() {
    printf("\n");
    printf("==========================================\n");
    printf("    VXLAN Implementation Test Suite\n");
    printf("==========================================\n");
    
    /* Run all tests */
    test_init();
    test_invalid_vni();
    test_vxlan_header();
    test_encapsulation();
    test_roundtrip();
    test_mac_learning();
    test_multi_vni();
    test_src_port_hash();
    test_checksum();
    test_mac_capacity();
    
    /* Summary */
    printf("\n");
    printf("==========================================\n");
    printf("             Test Results\n");
    printf("==========================================\n");
    printf("Tests passed: " ANSI_GREEN "%d" ANSI_RESET "\n", tests_passed);
    printf("Tests failed: " ANSI_RED "%d" ANSI_RESET "\n", tests_failed);
    printf("==========================================\n\n");
    
    return (tests_failed == 0) ? 0 : 1;
}
