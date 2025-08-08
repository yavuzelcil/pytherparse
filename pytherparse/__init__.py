from .pytherparse_native import (
    parse_packet,
    parse_pcap_file,
    ParsedPacket,
    Ethernet2Header,
    Ipv4Header,
    Ipv6Header,
    TcpHeader,
    UdpHeader,
)

def parse(file_path_or_bytes):
    """
    Parse a packet from raw bytes or a PCAP file
    
    Args:
        file_path_or_bytes: Either a file path to a PCAP file (str) or raw packet bytes
        
    Returns:
        A ParsedPacket or list of ParsedPackets
        
    Raises:
        TypeError: If the input is neither a string nor bytes
        ValueError: If the packet cannot be parsed
        IOError: If the PCAP file cannot be opened
    """
    if isinstance(file_path_or_bytes, str):
        return parse_pcap_file(file_path_or_bytes)
    elif isinstance(file_path_or_bytes, (bytes, bytearray)):
        return parse_packet(file_path_or_bytes)
    else:
        raise TypeError("parse() only accepts a file path (str) or raw bytes (bytes/bytearray)")

__all__ = [
    "parse",
    "parse_packet",
    "parse_pcap_file",
    "ParsedPacket",
    "Ethernet2Header",
    "Ipv4Header",
    "Ipv6Header",
    "TcpHeader",
    "UdpHeader",
]