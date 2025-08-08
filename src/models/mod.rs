//! Data models for parsed network packets
//!
//! This module contains data structures that represent parsed network packets
//! and related components.

// Declare submodules
mod parsed_packet;

// Re-export data structures
pub use parsed_packet::ParsedPacket;

// Note: Additional model types can be added here in the future
// For example:
// mod packet_builder;
// pub use packet_builder::PacketBuilder;