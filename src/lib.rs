use pyo3::prelude::*;

// Declare the modules
mod headers;
mod models;
mod parsers;

// Use the types and functions from our modules
use headers::{
    Ethernet2Header,
    Ipv4Header,
    Ipv6Header,
    TcpHeader,
    UdpHeader,
};
use models::ParsedPacket;
use parsers::{parse_packet, parse_pcap_file};

/// Python module for network packet parsing
/// 
/// This module provides functions and classes for parsing network packets
/// from raw bytes or PCAP files, using the etherparse Rust library.
#[pymodule]
fn pytherparse_native(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Add header classes
    m.add_class::<Ethernet2Header>()?;
    m.add_class::<Ipv4Header>()?;
    m.add_class::<Ipv6Header>()?;
    m.add_class::<TcpHeader>()?;
    m.add_class::<UdpHeader>()?;
    
    // Add packet model class
    m.add_class::<ParsedPacket>()?;
    
    // Add parsing functions
    m.add_function(wrap_pyfunction!(parse_packet, m)?)?;
    m.add_function(wrap_pyfunction!(parse_pcap_file, m)?)?;
    
    // Set module level documentation
    m.add("__doc__", "Python interface to etherparse packet parser")?;
    
    Ok(())
}