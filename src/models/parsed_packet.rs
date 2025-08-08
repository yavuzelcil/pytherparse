use pyo3::prelude::*;
use crate::headers::{Ethernet2Header, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader};

/// Represents a parsed network packet with various header components
/// 
/// This struct contains optional fields for different protocol headers
/// that may be present in a network packet. Each field is None if the
/// corresponding protocol is not present in the packet.
#[pyclass]
#[derive(Clone)]
pub struct ParsedPacket {
    /// Link layer header (Ethernet)
    #[pyo3(get)]
    pub link: Option<Ethernet2Header>,
    
    /// IPv4 header (if present)
    #[pyo3(get)]
    pub ipv4: Option<Ipv4Header>,
    
    /// IPv6 header (if present)
    #[pyo3(get)]
    pub ipv6: Option<Ipv6Header>,
    
    /// TCP header (if present)
    #[pyo3(get)]
    pub tcp: Option<TcpHeader>,
    
    /// UDP header (if present)
    #[pyo3(get)]
    pub udp: Option<UdpHeader>,
    
    /// Payload data (application layer content)
    #[pyo3(get)]
    pub payload: Vec<u8>,
}

#[pymethods]
impl ParsedPacket {
    /// Create a new empty ParsedPacket
    #[new]
    pub fn new() -> Self {
        Self {
            link: None,
            ipv4: None,
            ipv6: None,
            tcp: None,
            udp: None,
            payload: Vec::new(),
        }
    }
    
    /// Check if the packet contains an IPv4 header
    pub fn has_ipv4(&self) -> bool {
        self.ipv4.is_some()
    }
    
    /// Check if the packet contains an IPv6 header
    pub fn has_ipv6(&self) -> bool {
        self.ipv6.is_some()
    }
    
    /// Check if the packet contains a TCP header
    pub fn has_tcp(&self) -> bool {
        self.tcp.is_some()
    }
    
    /// Check if the packet contains a UDP header
    pub fn has_udp(&self) -> bool {
        self.udp.is_some()
    }
    
    /// Get the IP version of the packet (4, 6, or 0 if not an IP packet)
    pub fn ip_version(&self) -> u8 {
        if self.ipv4.is_some() {
            4
        } else if self.ipv6.is_some() {
            6
        } else {
            0
        }
    }
    
    /// Get the payload length
    pub fn payload_length(&self) -> usize {
        self.payload.len()
    }
    
    /// Get the payload as bytes
    pub fn get_payload(&self) -> &[u8] {
        &self.payload
    }
    
    /// Set or replace the payload
    pub fn set_payload(&mut self, data: Vec<u8>) {
        self.payload = data;
    }
}