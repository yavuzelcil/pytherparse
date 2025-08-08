//! Header modules for different network protocols
//!
//! This module contains wrappers for various network protocol headers
//! from the etherparse crate, providing a Python-friendly API.

// Declare submodules
mod ethernet;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;

// Re-export header structs so they can be imported directly from pytherparse.headers
pub use ethernet::Ethernet2Header;
pub use ipv4::Ipv4Header;
pub use ipv6::Ipv6Header;
pub use tcp::TcpHeader;
pub use udp::UdpHeader;

// This pattern allows users to import like:
// from pytherparse.headers import Ethernet2Header, Ipv4Header
// instead of:
// from pytherparse.headers.ethernet import Ethernet2Header