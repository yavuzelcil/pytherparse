import pytest
from pathlib import Path
import pytherparse

packet = bytes.fromhex("00005e0001ce6a05e395f3f9080045000028000040004006d99d8d52ac193424f3a2f53501bb626f575200000000500400009dfb0000")

print(pytherparse.parse_packet(packet))


result = pytherparse.parse_packet(packet)

def test_parse_packet():
    result = pytherparse.parse(Path("ping_heise.pcap"))
    
    assert result.link.source_mac == [9e:31:05:67:d3:b7]
    assert result.ip == 172.20.10.2


    for each_ethernet_packet in ethernetparser.parse_packet():
        pass
