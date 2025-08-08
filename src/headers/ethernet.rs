use pyo3::prelude::*;

/// Python wrapper for etherparse::Ethernet2Header
/// Represents an Ethernet II frame header
#[pyclass]
#[derive(Clone)]
pub struct Ethernet2Header {
    // Store the inner etherparse header - we're using composition pattern here
    // to ensure we can add Python-specific methods without modifying the original struct
    inner: etherparse::Ethernet2Header,
}

#[pymethods]
impl Ethernet2Header {
    /// Create a new Ethernet2Header with specified source, destination MAC addresses and EtherType
    /// 
    /// Args:
    ///     source: 6-byte MAC address of the sender
    ///     destination: 6-byte MAC address of the receiver
    ///     ether_type: 2-byte protocol identifier (e.g. 0x0800 for IPv4)
    #[new]
    pub fn new(source: [u8; 6], destination: [u8; 6], ether_type: u16) -> Self {
        Self {
            inner: etherparse::Ethernet2Header { 
                source, 
                destination, 
                ether_type 
            }
        }
    }

    /// Get the source MAC address
    #[getter]
    pub fn source(&self) -> [u8; 6] { 
        self.inner.source 
    }
    
    /// Get the destination MAC address
    #[getter]
    pub fn destination(&self) -> [u8; 6] { 
        self.inner.destination 
    }
    
    /// Get the EtherType field (protocol identifier)
    #[getter]
    pub fn ether_type(&self) -> u16 { 
        self.inner.ether_type 
    }

    /// Serialize the Ethernet header to bytes
    /// 
    /// Returns:
    ///     A vector of bytes representing the header
    pub fn to_bytes(&self) -> Vec<u8> {
        // Ethernet II header is always 14 bytes:
        // - 6 bytes destination MAC
        // - 6 bytes source MAC
        // - 2 bytes EtherType
        let mut buf = [0u8; 14];
        
        // Use etherparse's own serialization
        let bytes = self.inner.to_bytes();
        buf.copy_from_slice(&bytes);
        
        // Convert to Vec<u8> to return to Python
        buf.to_vec()
    }
}

/// Convert from etherparse::Ethernet2Header to our Ethernet2Header
/// This is used when parsing packets
impl From<etherparse::Ethernet2Header> for Ethernet2Header {
    fn from(header: etherparse::Ethernet2Header) -> Self {
        Self { inner: header }
    }
}

/// Convert from our Ethernet2Header to etherparse::Ethernet2Header
/// This is used when building packets
impl From<&Ethernet2Header> for etherparse::Ethernet2Header {
    fn from(header: &Ethernet2Header) -> Self {
        header.inner.clone()
    }
}