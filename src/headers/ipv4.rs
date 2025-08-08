use pyo3::prelude::*;

/// Python wrapper for etherparse::Ipv4Header
/// Represents an IPv4 header
#[pyclass]
#[derive(Clone)]
pub struct Ipv4Header {
    // Store the inner etherparse header - allows us to provide Python-friendly
    // methods while preserving the original structure
    inner: etherparse::Ipv4Header,
}

#[pymethods]
impl Ipv4Header {
    /// Create a new IPv4 header with the essential fields
    /// 
    /// Args:
    ///     source: 4-byte IPv4 source address
    ///     destination: 4-byte IPv4 destination address
    ///     ttl: Time to live value (default: 64)
    ///     protocol: Protocol identifier (e.g., 6 for TCP) (default: 0)
    #[new]
    #[pyo3(signature = (source, destination, ttl=64, protocol=0))]
    pub fn new(source: [u8; 4], destination: [u8; 4], ttl: u8, protocol: u8) -> Self {
        // Start with a default IPv4 header
        let mut header = etherparse::Ipv4Header::default();
        
        // Set the user-provided values
        header.source = source;
        header.destination = destination;
        header.time_to_live = ttl;
        header.protocol = protocol;
        
        // Return the wrapped header
        Self { inner: header }
    }

    /// Get the source IPv4 address
    #[getter]
    pub fn source(&self) -> [u8; 4] { 
        self.inner.source 
    }
    
    /// Get the destination IPv4 address
    #[getter]
    pub fn destination(&self) -> [u8; 4] { 
        self.inner.destination 
    }
    
    /// Get the Time to Live (TTL) value
    #[getter]
    pub fn ttl(&self) -> u8 { 
        self.inner.time_to_live 
    }
    
    /// Get the protocol identifier
    #[getter]
    pub fn protocol(&self) -> u8 { 
        self.inner.protocol 
    }
    
    /// Get the total header length in bytes
    #[getter]
    pub fn header_length(&self) -> u8 {
        self.inner.header_len() as u8
    }
    
    /// Get the identification field
    #[getter]
    pub fn identification(&self) -> u16 {
        self.inner.identification
    }
    
    /// Get the "Don't Fragment" flag
    #[getter]
    pub fn dont_fragment(&self) -> bool {
        self.inner.dont_fragment
    }
    
    /// Get the "More Fragments" flag
    #[getter]
    pub fn more_fragments(&self) -> bool {
        self.inner.more_fragments
    }
    
    /// Get the fragment offset
    #[getter]
    pub fn fragment_offset(&self) -> u16 {
        self.inner.fragments_offset
    }

    /// Serialize the IPv4 header to bytes
    /// 
    /// Returns:
    ///     A vector of bytes representing the header
    pub fn to_bytes(&self) -> Vec<u8> {
        // Get the size of the header
        let size = self.inner.header_len() as usize;
        
        // Create a buffer with the right size
        let mut buf = vec![0u8; size];
        
        // Use etherparse's own serialization
        self.inner.write(&mut buf).unwrap();
        
        // Return the buffer
        buf
    }
}

/// Convert from etherparse::Ipv4Header to our Ipv4Header
/// This is used when parsing packets
impl From<etherparse::Ipv4Header> for Ipv4Header {
    fn from(header: etherparse::Ipv4Header) -> Self {
        Self { inner: header }
    }
}

/// Convert from our Ipv4Header to etherparse::Ipv4Header
/// This is used when building packets
impl From<&Ipv4Header> for etherparse::Ipv4Header {
    fn from(header: &Ipv4Header) -> Self {
        header.inner.clone()
    }
}