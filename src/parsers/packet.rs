use pyo3::prelude::*;
use etherparse::{PacketHeaders, IpHeader, TransportHeader, SlicedPacket};
use crate::models::ParsedPacket;
use crate::headers::{Ethernet2Header, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader};

/// Parse a raw packet from bytes
/// 
/// Args:
///     data: Raw packet bytes (e.g., from a pcap file or network interface)
/// 
/// Returns:
///     ParsedPacket: A parsed packet with all detected headers and payload
/// 
/// Raises:
///     ValueError: If the packet cannot be parsed
#[pyfunction]
pub fn parse_packet(data: &[u8]) -> PyResult<ParsedPacket> {
    // Try to parse the packet using etherparse
    match PacketHeaders::from_ethernet_slice(data) {
        Ok(headers) => {
            // Create a new parsed packet
            let mut parsed = ParsedPacket::new();
            
            // Parse link layer (Ethernet)
            if let Some(link) = headers.link {
                parsed.link = Some(Ethernet2Header::from(link));
            }
            
            // Parse IP layer
            if let Some(ip) = headers.ip {
                match ip {
                    IpHeader::Version4(ipv4, _) => {
                        parsed.ipv4 = Some(Ipv4Header::from(ipv4));
                    },
                    IpHeader::Version6(ipv6, _) => {
                        parsed.ipv6 = Some(Ipv6Header::from(ipv6));
                    }
                }
            }
            
            // Parse transport layer
            if let Some(transport) = headers.transport {
                match transport {
                    TransportHeader::Tcp(tcp) => {
                        parsed.tcp = Some(TcpHeader::from(tcp));
                    },
                    TransportHeader::Udp(udp) => {
                        parsed.udp = Some(UdpHeader::from(udp));
                    },
                    // Other transport protocols can be handled here
                    _ => {
                        // We're ignoring other transport protocols for now
                    }
                }
            }
            
            // Extract payload if available
            if !headers.payload.is_empty() {
                parsed.set_payload(headers.payload.to_vec());
            }
            
            Ok(parsed)
        },
        // If parsing as Ethernet fails, try parsing as IP directly
        Err(_) => {
            match SlicedPacket::from_ip(data) {
                Ok(packet) => {
                    let mut parsed = ParsedPacket::new();
                    
                    // Parse IP layer
                    if let Some(ip) = packet.ip {
                        match ip {
                            etherparse::InternetSlice::Ipv4(ipv4, _) => {
                                parsed.ipv4 = Some(Ipv4Header::from(ipv4.to_header()));
                            },
                            etherparse::InternetSlice::Ipv6(ipv6, _) => {
                                parsed.ipv6 = Some(Ipv6Header::from(ipv6.to_header()));
                            }
                        }
                    }
                    
                    // Parse transport layer
                    if let Some(transport) = packet.transport {
                        match transport {
                            etherparse::TransportSlice::Tcp(tcp) => {
                                parsed.tcp = Some(TcpHeader::from(tcp.to_header()));
                            },
                            etherparse::TransportSlice::Udp(udp) => {
                                parsed.udp = Some(UdpHeader::from(udp.to_header()));
                            },
                            // Other transport protocols can be handled here
                            _ => {
                                // We're ignoring other transport protocols for now
                            }
                        }
                    }
                    
                    // Extract payload if available
                    if !packet.payload.is_empty() {
                        parsed.set_payload(packet.payload.to_vec());
                    }
                    
                    Ok(parsed)
                },
                Err(e) => {
                    // If all parsing attempts fail, return an error
                    Err(pyo3::exceptions::PyValueError::new_err(
                        format!("Failed to parse packet: {}", e)
                    ))
                }
            }
        }
    }
}