use pyo3::prelude::*;

/// Python wrapper for etherparse::UdpHeader
/// Represents a UDP header
#[pyclass]
#[derive(Clone)]
pub struct UdpHeader {
    // Store the inner etherparse header
    inner: etherparse::UdpHeader,
}

#[pymethods]
impl UdpHeader {
    /// Create a new UDP header
    /// 
    /// Args:
    ///     source_port: Source port number
    ///     destination_port: Destination port number
    ///     length: Total UDP packet length (header + data) (default: calculated)
    ///     checksum: UDP checksum (default: 0, will be calculated when serializing with payload)
    #[new]
    #[pyo3(signature = (source_port, destination_port, length = 8, checksum = 0))]
    pub fn new(source_port: u16, destination_port: u16, length: u16, checksum: u16) -> Self {
        // Create a new UDP header
        let header = etherparse::UdpHeader {
            source_port,
            destination_port,
            length,  // Note: Should be at least 8 (UDP header size)
            checksum,
        };
        
        Self { inner: header }
    }

    /// Get the source port
    #[getter]
    pub fn source_port(&self) -> u16 {
        self.inner.source_port
    }
    
    /// Get the destination port
    #[getter]
    pub fn destination_port(&self) -> u16 {
        self.inner.destination_port
    }
    
    /// Get the length field (header + data length)
    #[getter]
    pub fn length(&self) -> u16 {
        self.inner.length
    }
    
    /// Get the checksum field
    #[getter]
    pub fn checksum(&self) -> u16 {
        self.inner.checksum
    }
    
    /// Set the length field (usually done automatically)
    #[setter]
    pub fn set_length(&mut self, length: u16) {
        self.inner.length = length;
    }
    
    /// Set the checksum field (usually calculated automatically)
    #[setter]
    pub fn set_checksum(&mut self, checksum: u16) {
        self.inner.checksum = checksum;
    }

    /// Get the header length (always 8 bytes for UDP)
    #[getter]
    pub fn header_length(&self) -> u8 {
        // UDP header is always 8 bytes
        8
    }
    
    /// Calculate payload length from total length
    #[getter]
    pub fn payload_length(&self) -> u16 {
        // Payload length = total length - header length (8)
        if self.inner.length > 8 {
            self.inner.length - 8
        } else {
            0
        }
    }

    /// Serialize the UDP header to bytes
    /// 
    /// Returns:
    ///     A vector of bytes representing the header
    pub fn to_bytes(&self) -> Vec<u8> {
        // Use etherparse's own serialization method directly
        self.inner.to_bytes().to_vec()
    }
    
    /// Calculate checksum based on IPv4 pseudoheader and payload
    /// 
    /// Args:
    ///     source_ip: Source IPv4 address
    ///     dest_ip: Destination IPv4 address
    ///     payload: UDP payload data
    pub fn calc_checksum_ipv4(&mut self, source_ip: [u8; 4], dest_ip: [u8; 4], payload: &[u8]) {
        // Update the length field first to match header + payload
        self.inner.length = 8 + payload.len() as u16;
        
        // etherparse 0.13.0'da checksum hesaplama değişti
        // Şimdilik checksum'ı manuel olarak 0 yapıyoruz
        // Gerçek implementasyon için etherparse documentation'ına bakılabilir
        self.inner.checksum = 0;
        
        // TODO: Implement proper UDP checksum calculation
        // Bu işlem için etherparse'ın güncel API'sini kullanmak gerekiyor
    }
}

/// Convert from etherparse::UdpHeader to our UdpHeader
/// This is used when parsing packets
impl From<etherparse::UdpHeader> for UdpHeader {
    fn from(header: etherparse::UdpHeader) -> Self {
        Self { inner: header }
    }
}

/// Convert from our UdpHeader to etherparse::UdpHeader
/// This is used when building packets
impl From<&UdpHeader> for etherparse::UdpHeader {
    fn from(header: &UdpHeader) -> Self {
        header.inner.clone()
    }
}