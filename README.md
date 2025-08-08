# pytherparse

High-performance Python bindings for the Rust `etherparse` crate, providing fast and reliable network packet parsing capabilities. Built with PyO3 for seamless Python-Rust integration.

## 🚀 Features

- **Modular Architecture**: Clean separation of headers, models, and parsers
- **Protocol Support**: Ethernet II, IPv4, IPv6, TCP, UDP headers
- **High Performance**: Rust-powered parsing with zero-copy where possible
- **Python-Friendly API**: Intuitive interface with proper error handling
- **Packet Construction**: Build packets programmatically with `to_bytes()` methods
- **PCAP Support**: Parse packets from PCAP files (Unix systems)

## 📦 Installation

### From PyPI (Recommended)

```bash
pip install pytherparse
```

Pre-built wheels are available for:
- **Windows**: x86_64
- **macOS**: x86_64, Apple Silicon (ARM64)  
- **Linux**: x86_64, ARM64

### From Source

If you need to build from source or contribute to development:

```bash
# Clone the repository
git clone https://github.com/yourusername/pytherparse.git
cd pytherparse

# Install build dependencies
pip install -r requirements.txt

# Build and install in development mode
maturin develop

# Or build wheel for distribution
maturin build --release
```

### Requirements

- **Python**: 3.8+
- **Rust**: 1.70+ (only needed for building from source)

## 🎯 Quick Start

### Parse Raw Packet Bytes

```python
import pytherparse

# Example TCP packet with Ethernet + IPv4 + TCP headers
raw_bytes = bytes([
    # Ethernet Header
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  # Dst MAC
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,  # Src MAC
    0x08, 0x00,                          # EtherType (IPv4)
    # IPv4 Header
    0x45, 0x00, 0x00, 0x3c, 0x12, 0x34,  # Version, ToS, Length, ID
    0x40, 0x00, 0x40, 0x06, 0x00, 0x00,  # Flags, TTL, Protocol, Checksum
    192, 168, 1, 100,                    # Source IP
    8, 8, 8, 8,                         # Dest IP
    # TCP Header + payload...
])

packet = pytherparse.parse_packet(raw_bytes)
print(f"Protocol: IPv{packet.ip_version()}")
```

### Access Protocol Headers

```python
# Check which protocols are present
if packet.has_ipv4():
    ipv4 = packet.ipv4
    src_ip = ipv4.source
    print(f"Source: {src_ip[0]}.{src_ip[1]}.{src_ip[2]}.{src_ip[3]}")
    print(f"TTL: {ipv4.ttl}")
    print(f"Protocol: {ipv4.protocol}")

if packet.has_tcp():
    tcp = packet.tcp
    print(f"Ports: {tcp.source_port} → {tcp.destination_port}")
    print(f"Flags: SYN={tcp.syn}, ACK={tcp.ack}")

if packet.link:
    eth = packet.link
    src_mac = ':'.join(f'{b:02x}' for b in eth.source)
    print(f"Source MAC: {src_mac}")
```

### Parse PCAP Files

```python
# Parse entire PCAP file (Unix systems only)
packets = pytherparse.parse_pcap_file("capture.pcap")
for packet in packets:
    if packet.has_tcp() and packet.tcp.destination_port == 80:
        print(f"HTTP request: {packet.ipv4.source} → {packet.ipv4.destination}")
```

### Build Packets Programmatically

```python
# Create protocol headers
eth_header = pytherparse.Ethernet2Header(
    source=[0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    destination=[0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc],
    ether_type=0x0800  # IPv4
)

ipv4_header = pytherparse.Ipv4Header(
    source=[192, 168, 1, 1],
    destination=[8, 8, 8, 8],
    ttl=64,
    protocol=6  # TCP
)

tcp_header = pytherparse.TcpHeader(
    source_port=12345,
    destination_port=80
)

# Serialize to bytes
eth_bytes = eth_header.to_bytes()
ip_bytes = ipv4_header.to_bytes()
tcp_bytes = tcp_header.to_bytes()
```

## 🏗️ Architecture

```
pytherparse/
├── headers/          # Protocol header wrappers
│   ├── ethernet.rs   # Ethernet II frames
│   ├── ipv4.rs       # IPv4 headers
│   ├── ipv6.rs       # IPv6 headers
│   ├── tcp.rs        # TCP headers
│   └── udp.rs        # UDP headers
├── models/           # Data structures
│   └── parsed_packet.rs  # ParsedPacket container
├── parsers/          # Parsing logic
│   ├── packet.rs     # Raw packet parsing
│   └── pcap.rs       # PCAP file parsing
└── lib.rs           # PyO3 module definition
```

## 📚 API Reference

### ParsedPacket

The main container for parsed packet data:

```python
packet = pytherparse.parse_packet(data)

# Protocol detection
packet.has_ipv4()     # bool
packet.has_ipv6()     # bool  
packet.has_tcp()      # bool
packet.has_udp()      # bool
packet.ip_version()   # 0, 4, or 6

# Access headers (returns None if not present)
packet.link          # Ethernet2Header | None
packet.ipv4          # Ipv4Header | None
packet.ipv6          # Ipv6Header | None
packet.tcp           # TcpHeader | None
packet.udp           # UdpHeader | None

# Payload access
packet.payload              # bytes
packet.payload_length()     # int
packet.get_payload()        # bytes
packet.set_payload(data)    # None
```

### Protocol Headers

All headers support:
- **Getters**: Access to all protocol fields
- **Construction**: Create headers programmatically
- **Serialization**: `to_bytes()` method for packet building

## ⚠️ Platform Support

- **Packet parsing**: All platforms (Windows, macOS, Linux) - multiple architectures
- **PCAP parsing**: Unix systems only (requires libpcap)
- **Pre-built wheels**: Available for major platforms on PyPI
- **Python versions**: 3.9, 3.10, 3.11

## 🔧 Development

```bash
# Build for development
maturin develop

# Run tests
python tests/test_pp2_raw.py

# Build wheel
maturin build --release
```

## 🚀 Publishing to PyPI

For maintainers:

```bash
# Build wheels for all platforms
maturin build --release

# Upload to PyPI
maturin publish

# Or upload to TestPyPI first
maturin publish --repository testpypi
```

Pre-built wheels ensure users don't need Rust toolchain installed.

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional protocol support (ICMP, ARP, etc.)
- Performance optimizations
- Enhanced error handling
- More comprehensive testing

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [etherparse](https://github.com/JulianSchmid/etherparse) - Excellent Rust packet parsing
- [PyO3](https://pyo3.rs/) - Seamless Rust-Python bindings
- Rust and Python communities for amazing ecosystems

---
Built with ❤️ using Rust and Python
