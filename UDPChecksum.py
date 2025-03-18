import struct
import socket

def ip_to_bytes(ip):
    return socket.inet_aton(ip)

def udp_checksum(ip_src, ip_dst, udp_src, udp_dst, data):
    pseudo_header = ip_to_bytes(ip_src) + ip_to_bytes(ip_dst) 
    pseudo_header += struct.pack('!BBH', 0, 17, len(data) + 8)
    
    udp_header = struct.pack('!HHHH', udp_src, udp_dst, len(data) + 8, 0)
    packet = pseudo_header + udp_header + data
    
    if len(packet) % 2 == 1:
        packet += b'\x00'

    checksum = 0
    for i in range(0, len(packet), 2):
        word = (packet[i] << 8) + packet[i+1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    checksum = ~checksum & 0xFFFF
    return checksum

test_cases = [
    ("192.168.1.1", "192.168.1.2", 12345, 80, b"Hello, UDP!"),
    ("10.0.0.1", "10.0.0.2", 5000, 8080, b"Test UDP Checksum"),
    ("172.16.100.5", "172.16.200.10", 53, 53, b"A" * 512),
    ("192.168.100.1", "192.168.100.2", 4000, 1234, b""),
    ("192.168.50.10", "192.168.50.20", 9999, 5555, bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09])),
]

for i, (ip_src, ip_dst, udp_src, udp_dst, data) in enumerate(test_cases, 1):
    checksum = udp_checksum(ip_src, ip_dst, udp_src, udp_dst, data)
    print(f"Tes {i}: UDP Checksum = {checksum:04X}")
