use pyo3::prelude::*;

/// Python wrapper for etherparse::TcpHeader
/// Represents a TCP header
#[pyclass]
#[derive(Clone)]
pub struct TcpHeader {
    // Store the inner etherparse header for delegation and preservation
    // of the original structure's functionality
    inner: etherparse::TcpHeader,
}

#[pymethods]
impl TcpHeader {
    /// Create a new TCP header with the essential fields
    /// 
    /// Args:
    ///     source_port: Source port number
    ///     destination_port: Destination port number
    ///     sequence_number: Sequence number (default: 0)
    ///     acknowledgment_number: Acknowledgment number (default: 0)
    ///     window_size: Window size in bytes (default: 64240)
    #[new]
    #[pyo3(signature = (source_port, destination_port, sequence_number = 0, acknowledgment_number = 0, window_size = 64240))]
    pub fn new(
        source_port: u16, 
        destination_port: u16, 
        sequence_number: u32, 
        acknowledgment_number: u32,
        window_size: u16
    ) -> Self {
        // Create a default TCP header
        let mut header = etherparse::TcpHeader::default();
        
        // Set the user-provided values
        header.source_port = source_port;
        header.destination_port = destination_port;
        header.sequence_number = sequence_number;
        header.acknowledgment_number = acknowledgment_number;
        header.window_size = window_size;
        
        // Return the wrapped header
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
    
    /// Get the sequence number
    #[getter]
    pub fn sequence_number(&self) -> u32 {
        self.inner.sequence_number
    }
    
    /// Get the acknowledgment number
    #[getter]
    pub fn acknowledgment_number(&self) -> u32 {
        self.inner.acknowledgment_number
    }
    
    /// Get the window size
    #[getter]
    pub fn window_size(&self) -> u16 {
        self.inner.window_size
    }
    
    /// Get the urgent pointer
    #[getter]
    pub fn urgent_pointer(&self) -> u16 {
        self.inner.urgent_pointer
    }
    
    /// Get the header length in 32-bit words
    #[getter]
    pub fn data_offset(&self) -> u8 {
        self.inner.data_offset()
    }

    /// Get the header length in bytes
    #[getter]
    pub fn header_length(&self) -> u8 {
        self.inner.header_len() as u8
    }
    
    // TCP Flag getters
    
    /// Get the SYN flag (synchronize sequence numbers)
    #[getter]
    pub fn syn(&self) -> bool {
        self.inner.syn
    }
    
    /// Get the ACK flag (acknowledgment field is significant)
    #[getter]
    pub fn ack(&self) -> bool {
        self.inner.ack
    }
    
    /// Get the PSH flag (push function)
    #[getter]
    pub fn psh(&self) -> bool {
        self.inner.psh
    }
    
    /// Get the RST flag (reset the connection)
    #[getter]
    pub fn rst(&self) -> bool {
        self.inner.rst
    }
    
    /// Get the FIN flag (no more data from sender)
    #[getter]
    pub fn fin(&self) -> bool {
        self.inner.fin
    }
    
    /// Get the URG flag (urgent pointer field is significant)
    #[getter]
    pub fn urg(&self) -> bool {
        self.inner.urg
    }
    
    /// Get the ECE flag (ECN-Echo)
    #[getter]
    pub fn ece(&self) -> bool {
        self.inner.ece
    }
    
    /// Get the CWR flag (Congestion Window Reduced)
    #[getter]
    pub fn cwr(&self) -> bool {
        self.inner.cwr
    }
    
    // TCP Flag setters
    
    /// Set the SYN flag (synchronize sequence numbers)
    #[setter]
    pub fn set_syn(&mut self, value: bool) {
        self.inner.syn = value;
    }
    
    /// Set the ACK flag (acknowledgment field is significant)
    #[setter]
    pub fn set_ack(&mut self, value: bool) {
        self.inner.ack = value;
    }
    
    /// Set the PSH flag (push function)
    #[setter]
    pub fn set_psh(&mut self, value: bool) {
        self.inner.psh = value;
    }
    
    /// Set the RST flag (reset the connection)
    #[setter]
    pub fn set_rst(&mut self, value: bool) {
        self.inner.rst = value;
    }
    
    /// Set the FIN flag (no more data from sender)
    #[setter]
    pub fn set_fin(&mut self, value: bool) {
        self.inner.fin = value;
    }
    
    /// Set the URG flag (urgent pointer field is significant)
    #[setter]
    pub fn set_urg(&mut self, value: bool) {
        self.inner.urg = value;
    }

    /// Serialize the TCP header to bytes
    /// 
    /// Returns:
    ///     A vector of bytes representing the header
    pub fn to_bytes(&self) -> Vec<u8> {
        // Calculate the size of the header (minimum 20 bytes)
        let size = self.inner.header_len() as usize;
        
        // Create a buffer with the right size
        let mut buf = vec![0u8; size];
        
        // Use etherparse's own serialization
        self.inner.write(&mut buf).unwrap();
        
        // Return the buffer
        buf
    }
}

/// Convert from etherparse::TcpHeader to our TcpHeader
/// This is used when parsing packets
impl From<etherparse::TcpHeader> for TcpHeader {
    fn from(header: etherparse::TcpHeader) -> Self {
        Self { inner: header }
    }
}

/// Convert from our TcpHeader to etherparse::TcpHeader
/// This is used when building packets
impl From<&TcpHeader> for etherparse::TcpHeader {
    fn from(header: &TcpHeader) -> Self {
        header.inner.clone()
    }
}