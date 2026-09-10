"""
RTP Packet Parser
Parse pcap/pcapng files and extract all RTP packet information.
"""
from scapy.all import rdpcap, IP, UDP, Raw
from collections import defaultdict
import os


def parse_rtp_header(payload: bytes):
    """Parse RTP header fields.
    
    Returns:
        (pt, seq, timestamp, ssrc, payload_bytes) or None if not a valid RTP packet.
        payload_bytes is the raw encoded media data after the 12-byte RTP header.
    """
    if len(payload) < 12:
        return None
    b0 = payload[0]
    version = (b0 >> 6) & 0x03
    if version != 2:
        return None
    pt = payload[1] & 0x7F
    seq = int.from_bytes(payload[2:4], 'big')
    ts = int.from_bytes(payload[4:8], 'big')
    ssrc = int.from_bytes(payload[8:12], 'big')
    return (pt, seq, ts, ssrc, payload[12:])


def extract_rtp_packets(filepath: str, include_payload: bool = False) -> dict:
    """Extract all RTP packets from a pcap file.
    
    Args:
        filepath: Path to pcap/pcapng file.
        include_payload: If True, store the raw RTP payload bytes for each packet.
                         Set to False for upload/preview to save memory.
        
    Returns:
        {
            'packets': {(ssrc, seq): (capture_time, rtp_ts, pt, src_ip, dst_ip, src_port, dst_port, [payload])},
            'total_count': int,
            'ips': set,
            'ssrcs': set,
            'streams': {ssrc: {'count': int, 'pt': set, 'src_ip': str, 'dst_ip': str, ...}}
        }
    """
    pkts = rdpcap(filepath)
    packets = {}
    ips = set()
    ssrcs = set()
    streams = defaultdict(lambda: {'count': 0, 'pt': set(), 'ips': set(), 'port_pairs': set()})
    
    for p in pkts:
        if IP in p and UDP in p and Raw in p:
            rtp = parse_rtp_header(bytes(p[Raw]))
            if rtp:
                pt, seq, ts, ssrc, payload = rtp
                src_ip = p[IP].src
                dst_ip = p[IP].dst
                src_port = p[UDP].sport
                dst_port = p[UDP].dport
                key = (ssrc, seq)
                
                # Only keep the first occurrence of each packet (dedup)
                if key not in packets:
                    if include_payload:
                        packets[key] = (float(p.time), ts, pt, src_ip, dst_ip, src_port, dst_port, payload)
                    else:
                        packets[key] = (float(p.time), ts, pt, src_ip, dst_ip, src_port, dst_port)
                
                ips.add(src_ip)
                ips.add(dst_ip)
                ssrcs.add(ssrc)
                streams[ssrc]['count'] += 1
                streams[ssrc]['pt'].add(pt)
                streams[ssrc]['ips'].add((src_ip, dst_ip))
                streams[ssrc]['port_pairs'].add((src_ip, src_port, dst_ip, dst_port))
    
    # Convert sets to lists in streams (for JSON serialization)
    streams_clean = {}
    for ssrc, info in streams.items():
        if info['count'] >= 10:  # Filter out streams with too few packets
            streams_clean[ssrc] = {
                'count': info['count'],
                'pt': sorted(info['pt']),
                'ips': [list(ip) for ip in info['ips']],
                'port_pairs': [list(pp) for pp in info['port_pairs']],
            }
    
    return {
        'packets': packets,
        'total_count': len(packets),
        'ips': ips,
        'ssrcs': ssrcs,
        'streams': streams_clean,
    }


def get_packet_time(packets: dict, ssrc: int, seq: int):
    """Get the capture time of a specific packet."""
    key = (ssrc, seq)
    if key in packets:
        return packets[key][0]
    return None


def get_stream_packets(packets: dict, ssrc: int) -> list:
    """Get all packets for a given SSRC, sorted by capture time.
    
    Returns:
        [(capture_time, seq, rtp_ts, pt, src_ip, dst_ip, src_port, dst_port, [payload]), ...]
        The payload element is present only if include_payload=True was used during extraction.
    """
    result = []
    for k, v in packets.items():
        if k[0] == ssrc:
            result.append((v[0], k[1], v[1], v[2], v[3], v[4], v[5], v[6]) + v[7:])
    result.sort(key=lambda x: x[0])
    return result