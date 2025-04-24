# pytherparse

`pytherparse` provides Python bindings for the `etherparse` Rust crate, enabling high-performance packet parsing in Python via Rust and `pyo3`. This library is designed for developers working with network packets who need a fast and reliable way to parse Ethernet, IP, and transport layer headers.

## Features
- Parse Ethernet, IP, and transport layer headers.
- High performance using Rust's `etherparse` crate.
- Easy-to-use Python interface.

## Installation

To install `pytherparse`, you need to have Rust and Python installed on your system. You can build and install the package using [Maturin](https://github.com/PyO3/maturin):

```bash
# Install maturin if not already installed
pip install maturin

# Build and install pytherparse
maturin develop

``` 

## Usage

Here’s an example of how to use `pytherparse` to parse a network packet:

```python
import pytherparse

# Example packet data (Ethernet + IP + TCP headers)
packet_data = b'\x00\x1a\xa0\x00\x00\x01\x00\x1a\xa0\x00\x00\x02\x08\x00' \
              b'\x45\x00\x00\x28\x6f\x22\x40\x00\x40\x06\xb1\xe6\xc0\xa8' \
              b'\x00\x01\xc0\xa8\x00\x02\x04\xd2\x00\x50\x00\x00\x00\x00' \
              b'\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00'

# Parse the packet
result = pytherparse.parse_packet(packet_data)

# Print the parsed headers
print(result)
```

### Example Output:
```
Ethernet Header: Ethernet2Header { destination: [0, 26, 160, 0, 0, 1], source: [0, 26, 160, 0, 0, 2], ethertype: IPv4 }
IP Header: Ipv4Header { source: 192.168.0.1, destination: 192.168.0.2, protocol: TCP }
Transport Header: TcpHeader { source_port: 1234, destination_port: 80 }
```

## Development

To contribute to `pytherparse`, clone the repository and make your changes. Use `maturin develop` to test your changes locally.

```bash
# Clone the repository
git clone https://github.com/yourusername/pytherparse.git
cd pytherparse

# Install the package locally
maturin develop
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [etherparse](https://github.com/rusticata/etherparse) for the Rust packet parsing library.
- [pyo3](https://pyo3.rs/) for enabling seamless Rust-Python bindings.

