use pyo3::prelude::*;
use pyo3::types::PyList;
use etherparse::{PacketBuilder, PacketHeaders, IpHeader, TransportHeader};

// pcap is only imported on Unix systems
#[cfg(unix)]
use pcap::Capture;

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyIpv4Header {
    #[pyo3(get)]
    pub source: [u8; 4],
    #[pyo3(get)]
    pub destination: [u8; 4],
    #[pyo3(get)]
    pub ttl: u8,
}

impl From<etherparse::Ipv4Header> for PyIpv4Header {
    fn from(header: etherparse::Ipv4Header) -> Self {
        PyIpv4Header {
            source: header.source,
            destination: header.destination,
            ttl: header.time_to_live,
        }
    }
}

#[pymethods]
impl PyIpv4Header {
    /// Create a new IPv4 header instance for packet construction.
    #[new]
    pub fn new(source: [u8; 4], destination: [u8; 4], ttl: u8) -> Self {
        PyIpv4Header { source, destination, ttl }
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyTcpHeader {
    #[pyo3(get)]
    pub source_port: u16,
    #[pyo3(get)]
    pub destination_port: u16,
    #[pyo3(get)]
    pub syn: bool,
    #[pyo3(get)]
    pub ack: bool,
}

impl From<etherparse::TcpHeader> for PyTcpHeader {
    fn from(header: etherparse::TcpHeader) -> Self {
        PyTcpHeader {
            source_port: header.source_port,
            destination_port: header.destination_port,
            syn: header.syn,
            ack: header.ack,
        }
    }
}

#[pymethods]
impl PyTcpHeader {
    /// Create a new TCP header instance for packet construction.
    #[new]
    pub fn new(source_port: u16, destination_port: u16, syn: bool, ack: bool) -> Self {
        PyTcpHeader {
            source_port,
            destination_port,
            syn,
            ack,
        }
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyEthernetHeader {
    #[pyo3(get)]
    pub source: [u8; 6],
    #[pyo3(get)]
    pub destination: [u8; 6],
    #[pyo3(get)]
    pub ether_type: u16,
}

impl From<etherparse::Ethernet2Header> for PyEthernetHeader {
    fn from(header: etherparse::Ethernet2Header) -> Self {
        PyEthernetHeader {
            source: header.source,
            destination: header.destination,
            ether_type: header.ether_type,
        }
    }
}

#[pymethods]
impl PyEthernetHeader {
    /// Create a new Ethernet II header instance for packet construction.
    #[new]
    pub fn new(source: [u8; 6], destination: [u8; 6], ether_type: u16) -> Self {
        PyEthernetHeader { source, destination, ether_type }
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyUdpHeader {
    #[pyo3(get)]
    pub source_port: u16,
    #[pyo3(get)]
    pub destination_port: u16,
}

impl From<etherparse::UdpHeader> for PyUdpHeader {
    fn from(header: etherparse::UdpHeader) -> Self {
        PyUdpHeader {
            source_port: header.source_port,
            destination_port: header.destination_port,
        }
    }
}

#[pymethods]
impl PyUdpHeader {
    /// Create a new UDP header instance for packet construction.
    #[new]
    pub fn new(source_port: u16, destination_port: u16) -> Self {
        PyUdpHeader { source_port, destination_port }
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyIcmpv6Header {
    #[pyo3(get)]
    pub checksum: u16,
    #[pyo3(get)]
    pub type_str: String,
}

impl From<etherparse::Icmpv6Header> for PyIcmpv6Header {
    fn from(header: etherparse::Icmpv6Header) -> Self {
        PyIcmpv6Header {
            checksum: header.checksum,
            type_str: format!("{:?}", header.icmp_type),
        }
    }
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    #[pyo3(get)]
    pub link: Option<PyEthernetHeader>,
    #[pyo3(get)]
    pub ip: Option<PyIpv4Header>,
    #[pyo3(get)]
    pub transport: Option<PyTcpHeader>,
    #[pyo3(get)]
    pub icmpv6: Option<PyIcmpv6Header>,
}

#[pyfunction]
pub fn parse_packet(data: &[u8]) -> PyResult<ParsedPacket> {
    match PacketHeaders::from_ethernet_slice(data) {
        Ok(headers) => {
            let icmpv6 = match &headers.transport {
                Some(TransportHeader::Icmpv6(icmpv6)) => Some(PyIcmpv6Header::from(icmpv6.clone())),
                _ => None,
            };
            let parsed = ParsedPacket {
                link: headers.link.map(PyEthernetHeader::from),
                ip: match headers.ip {
                    Some(IpHeader::Version4(ip, _)) => Some(PyIpv4Header::from(ip)),
                    _ => None,
                },
                transport: match headers.transport {
                    Some(TransportHeader::Tcp(tcp)) => Some(PyTcpHeader::from(tcp)),
                    _ => None,
                },
                icmpv6,
            };
            Ok(parsed)
        },
        Err(e) => Err(pyo3::exceptions::PyValueError::new_err(format!("Parsing failed: {}", e))),
    }
}

#[pyfunction]
pub fn build_packet(
    ethernet: PyRef<'_, PyEthernetHeader>,
    ip: PyRef<'_, PyIpv4Header>,
    udp: PyRef<'_, PyUdpHeader>,
    payload: &[u8],
) -> PyResult<Vec<u8>> {
    let builder = PacketBuilder::ethernet2(ethernet.source, ethernet.destination)
        .ipv4(ip.source, ip.destination, ip.ttl)
        .udp(udp.source_port, udp.destination_port);
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut packet, payload)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!(
            "Building failed: {}",
            e
        )))?;
    Ok(packet)
}

// Real implementation for Unix systems
#[cfg(unix)]
#[pyfunction]
pub fn parse_pcap_file(py: Python<'_>, path: String) -> PyResult<Py<PyList>> {
    let mut packets = Vec::new();

    let mut cap = Capture::from_file(path).map_err(|e| {
        pyo3::exceptions::PyIOError::new_err(format!("Failed to open pcap file: {}", e))
    })?;

    while let Ok(packet) = cap.next_packet() {
        if let Ok(headers) = PacketHeaders::from_ethernet_slice(&packet.data) {
            let icmpv6 = match &headers.transport {
                Some(TransportHeader::Icmpv6(icmpv6)) => Some(PyIcmpv6Header::from(icmpv6.clone())),
                _ => None,
            };
            let parsed = ParsedPacket {
                link: headers.link.map(PyEthernetHeader::from),
                ip: match headers.ip {
                    Some(IpHeader::Version4(ip, _)) => Some(PyIpv4Header::from(ip)),
                    _ => None,
                },
                transport: match headers.transport {
                    Some(TransportHeader::Tcp(tcp)) => Some(PyTcpHeader::from(tcp)),
                    _ => None,
                },
                icmpv6,
            };
            packets.push(parsed);
        }
    }

    let py_packets: Vec<_> = packets
        .into_iter()
        .map(|pkt| Py::new(py, pkt).unwrap())
        .collect();

    let list = PyList::new(py, py_packets)?;
    Ok(list.into())
}

// Stub function for Windows systems
#[cfg(windows)]
#[pyfunction]
pub fn parse_pcap_file(_py: Python<'_>, _path: String) -> PyResult<Py<PyList>> {
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        "parse_pcap_file is not supported on Windows.",
    ))
}

#[pymodule]
fn pytherparse_native(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_packet, m)?)?;
    m.add_function(wrap_pyfunction!(parse_pcap_file, m)?)?;
    m.add_function(wrap_pyfunction!(build_packet, m)?)?;
    m.add_class::<ParsedPacket>()?;
    m.add_class::<PyIpv4Header>()?;
    m.add_class::<PyTcpHeader>()?;
    m.add_class::<PyEthernetHeader>()?;
    m.add_class::<PyUdpHeader>()?;
    m.add_class::<PyIcmpv6Header>()?;
    Ok(())
}