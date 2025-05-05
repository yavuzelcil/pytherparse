# pytherparse

`pytherparse` provides Python bindings for the `etherparse` Rust crate, enabling high-performance packet parsing in Python via Rust and `pyo3`. This library is designed for developers working with network packets who need a fast and reliable way to parse Ethernet, IP, and transport layer headers.

> **Note**: Internally, the compiled Rust extension is named `pytherparse_native`, but it is exposed to Python via the `pytherparse` package using an interface defined in `__init__.py`.

## Features
- Parse Ethernet, IP, and transport layer headers.
- High performance using Rust's `etherparse` crate.
- Easy-to-use Python interface.



## Usage

You can use `pytherparse` directly in your Python code or test it using the provided `test_parse.py` script.

### Example: Parsing raw packet bytes

```python
import pytherparse

# Parse a packet from raw bytes
packet = bytes.fromhex("00005e0001ce6a05e395f3f9080045000028000040004006d99d8d52ac193424f3a2f53501bb626f575200000000500400009dfb0000")

parsed = pytherparse.parse(packet)
print(parsed.ip.source)
```

### Example: Parsing packets from a PCAP file

```python
# Or parse packets from a pcap file
packets = pytherparse.parse("example.pcap")
for pkt in packets:
    if pkt.ip:
        print(f"{pkt.ip.source} → {pkt.ip.destination}")
```

### Installation Note

Make sure you have installed `pytherparse` using `maturin develop`. Due to PyO3 import conflicts, the compiled Rust extension module is named `pytherparse_native`, but you should always import from the `pytherparse` package as shown above.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [etherparse](https://github.com/rusticata/etherparse) for the Rust packet parsing library.
- [pyo3](https://pyo3.rs/) for enabling seamless Rust-Python bindings.
