use pyo3::prelude::*;
use pyo3::types::PyList;
use crate::parsers::packet::parse_packet;

// pcap is only imported on Unix systems since libpcap isn't well-supported on Windows
#[cfg(unix)]
use pcap::Capture;

/// Parse a PCAP file and extract all packets
/// 
/// Args:
///     path: Path to the PCAP file
/// 
/// Returns:
///     List[ParsedPacket]: A list of parsed packets
/// 
/// Raises:
///     IOError: If the file cannot be opened
///     ValueError: If the file is not a valid PCAP file
#[cfg(unix)]
#[pyfunction]
pub fn parse_pcap_file(py: Python<'_>, path: String) -> PyResult<Py<PyList>> {
    // Open the PCAP file
    let mut cap = match Capture::from_file(path) {
        Ok(cap) => cap,
        Err(e) => {
            return Err(pyo3::exceptions::PyIOError::new_err(
                format!("Failed to open pcap file: {}", e)
            ));
        }
    };
    
    // Create a Python list to store the parsed packets
    let packets = PyList::empty(py);
    
    // Process each packet in the PCAP file
    // pcap kütüphanesinde doğru iterator kullanımı:
    while let Ok(packet) = cap.next_packet() {
        // Parse the packet
        match parse_packet(packet.data) {
            Ok(parsed) => {
                // Add the parsed packet to the list - deprecated warning'i düzelttik
                packets.append(parsed.into_pyobject(py)?)?;
            },
            Err(_) => {
                // Skip packets that can't be parsed
                continue;
            }
        }
    }
    
    // Return the list of parsed packets
    Ok(packets.into())
}

/// Stub function for Windows systems
#[cfg(not(unix))]
#[pyfunction]
pub fn parse_pcap_file(_py: Python<'_>, _path: String) -> PyResult<Py<PyList>> {
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        "parse_pcap_file is not supported on Windows."
    ))
}
