# VXLAN (RFC 7348) Minimal implementation 

## Complete Implementation Package

This package provides a production-ready VXLAN implementation based on RFC 7348.

---

## What's Included

1. ** VXLAN Stack**
   - Header files with protocol definitions
   - Encapsulation engine
   - Decapsulation engine
   - MAC learning table
   - Utility functions

2. **Documentation**
   - README.md 

3. **Build System**
   - Makefile for easy compilation
   - Library (libvxlan.a)
   - test programs

---

## Quick Start

### Build Everything
```bash
make clean
make
```

This creates:
- `libvxlan.a` - Static library
- `test_vtep` - VTEP demonstration
- `test_vxlan` - Unit tests

### Run Example
```bash
# As root (for raw sockets)
sudo ./test_vtep
```

---

---

## Implementation Details

### Core Features

 **RFC 7348 Compliant**
- Complete VXLAN header (8 bytes)
- I-flag validation
- 24-bit VNI support (16M segments)
- UDP port 4789 (IANA assigned)

 **Encapsulation/Decapsulation**
- Full packet encapsulation (Eth + IP + UDP + VXLAN)
- Header validation on decapsulation
- Checksum calculation (IP/UDP)
- MTU handling

 **MAC Learning**
- Hash table implementation
- Automatic aging (configurable timeout)
- Thread-safe operations
- Source learning from packets

 **Performance Features**
- UDP source port hashing (ECMP support)
- Zero-copy where possible
- Efficient MAC table lookups

### VXLAN Packet Structure

```
+------------------+
| Outer Ethernet   | 14 bytes
+------------------+
| Outer IP         | 20 bytes (IPv4)
+------------------+
| Outer UDP        | 8 bytes (port 4789)
+------------------+
| VXLAN Header     | 8 bytes
+------------------+
| Inner Ethernet   | 14+ bytes
+------------------+
| Payload          | Variable
+------------------+

Total Overhead: ~50 bytes
```

---

## Usage Example

### Basic Encapsulation

```c
#include "vxlan.h"

int main() {
    vxlan_ctx_t ctx;
    uint32_t local_ip = inet_addr("192.168.1.100");
    uint32_t vni = 100;
    
    // Initialize
    if (vxlan_init(&ctx, local_ip, vni) != 0) {
        perror("vxlan_init failed");
        return 1;
    }
    
    // Encapsulate a frame
    uint8_t inner_frame[1500];
    uint8_t outer_packet[9000];
    size_t outer_len;
    uint32_t dst_vtep = inet_addr("192.168.1.200");
    
    // ... populate inner_frame ...
    
    if (vxlan_encapsulate(&ctx, inner_frame, sizeof(inner_frame),
                          outer_packet, &outer_len, dst_vtep) == 0) {
        // Send outer_packet over network
        send(sockfd, outer_packet, outer_len, 0);
    }
    
    // Cleanup
    vxlan_cleanup(&ctx);
    return 0;
}
```



## Debugging

### Packet Dumping

```c
// Enable packet dumps
vxlan_dump_packet(packet, len, "TX");
```

Output shows:
- Outer/inner Ethernet headers
- IP/UDP headers
- VXLAN header with VNI
- Payload hex dump

### Logging

Set debug level:
```c
// In your code
#define VXLAN_DEBUG 1
```

---

## Advanced Topics

### Multicast Support

For BUM (Broadcast, Unknown-unicast, Multicast) traffic:

```c
ctx.vtep.multicast_ip = inet_addr("239.1.1.1");

// When destination MAC unknown, use multicast
if (vxlan_mac_lookup(&ctx, dst_mac, vni, &remote_vtep) != 0) {
    // Use multicast IP as destination
    remote_vtep = ctx.vtep.multicast_ip;
}
```



## Further Reading

- **RFC 7348** - VXLAN Specification
- **reference** - folder which consists of additional details
- **RFC 768** - UDP Protocol
- **RFC 791** - Internet Protocol
- **RFC 1071** - IP Checksum Computation


