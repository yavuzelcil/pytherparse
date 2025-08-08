use pyo3::prelude::*;

/// Python wrapper for etherparse::Ipv6Header
/// Represents an IPv6 header
#[pyclass]
#[derive(Clone)]
pub struct Ipv6Header {
    // Store the inner etherparse header
    inner: etherparse::Ipv6Header,
}

#[pymethods]
impl Ipv6Header {
    /// Create a new IPv6 header with essential fields
    /// 
    /// Args:
    ///     source: 16-byte IPv6 source address
    ///     destination: 16-byte IPv6 destination address
    ///     hop_limit: Hop limit value (default: 64)
    ///     next_header: Next header identifier (default: 0)
    #[new]
    #[pyo3(signature=(source, destination, hop_limit=64, next_header=0, flow_label=0))]
    pub fn new(
        source: [u8; 16], 
        destination: [u8; 16], 
        hop_limit: u8, 
        next_header: u8,
        flow_label: u32
    ) -> Self {
        // Start with a default IPv6 header
        let mut header = etherparse::Ipv6Header::default();
        
        // Set the user-provided values
        header.source = source;
        header.destination = destination;
        header.hop_limit = hop_limit;
        header.next_header = next_header;
        
        // Flow label is only 20 bits, ensure it's masked
        header.flow_label = flow_label & 0xFFFFF;
        
        // Return the wrapped header
        Self { inner: header }
    }

    /// Get the source IPv6 address
    #[getter]
    pub fn source(&self) -> [u8; 16] { 
        self.inner.source 
    }
    
    /// Get the destination IPv6 address
    #[getter]
    pub fn destination(&self) -> [u8; 16] { 
        self.inner.destination 
    }
    
    /// Get the hop limit value
    #[getter]
    pub fn hop_limit(&self) -> u8 { 
        self.inner.hop_limit 
    }
    
    /// Get the next header field (protocol identifier)
    #[getter]
    pub fn next_header(&self) -> u8 { 
        self.inner.next_header 
    }
    
    /// Get the traffic class
    #[getter]
    pub fn traffic_class(&self) -> u8 {
        self.inner.traffic_class
    }
    
    /// Get the flow label
    #[getter]
    pub fn flow_label(&self) -> u32 {
        self.inner.flow_label
    }
    
    /// Get the payload length
    #[getter]
    pub fn payload_length(&self) -> u16 {
        self.inner.payload_length
    }
    
    /// Get the total header length (fixed for IPv6 base header)
    #[getter]
    pub fn header_length(&self) -> u8 {
        // IPv6 base header is always 40 bytes
        40
    }

    /// Serialize the IPv6 header to bytes
    /// 
    /// Returns:
    ///     A vector of bytes representing the header
    pub fn to_bytes(&self) -> Vec<u8> {
        // IPv6 header is always 40 bytes
        let mut buf = vec![0u8; 40];
        
        // Use etherparse's own serialization
        self.inner.write(&mut buf).unwrap();
        
        // Return the buffer
        buf
    }
}

/// Convert from etherparse::Ipv6Header to our Ipv6Header
/// This is used when parsing packets
impl From<etherparse::Ipv6Header> for Ipv6Header {
    fn from(header: etherparse::Ipv6Header) -> Self {
        Self { inner: header }
    }
}

/// Convert from our Ipv6Header to etherparse::Ipv6Header
/// This is used when building packets
impl From<&Ipv6Header> for etherparse::Ipv6Header {
    fn from(header: &Ipv6Header) -> Self {
        header.inner.clone()
    }
}