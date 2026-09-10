"""
Media Extractor
Reconstruct audio and video from RTP packet payloads.
"""
import os
import json
import struct
import wave
import audioop
import subprocess
from datetime import datetime
from collections import defaultdict

from analyzer.stream_classifier import AUDIO_PT, VIDEO_PT_RANGE, get_pt_name, identify_direction

# Audio codec constants
PT_PCMU = 0    # G.711 μ-law
PT_PCMA = 8    # G.711 A-law
PT_G722 = 9    # G.722
PT_GSM = 3     # GSM
PT_G729 = 18   # G.729

# G.711 packetization: typically 20ms per packet = 160 samples at 8kHz
G711_SAMPLES_PER_PACKET = 160
G711_SAMPLE_RATE = 8000

# Supported audio codecs for direct reconstruction
SUPPORTED_AUDIO = {PT_PCMU, PT_PCMA}
# Audio codecs that need external tools
UNSUPPORTED_AUDIO = {PT_G722, PT_GSM, PT_G729, 0, 3, 8, 9, 18}


def _endpoint_direction(dst_ip: str, server_ip: str, role: str) -> str:
    """Determine stream direction relative to the capture point's endpoint.
    
    Semantics: 'outbound' = media SENT by the endpoint where the capture was taken,
               'inbound'  = media RECEIVED by that endpoint.
    
    - Capture at the server (fs): dst==server means arriving at FS -> inbound;
      src==server means FS sent it -> outbound.
    - Capture at an endpoint (seat/terminal): dst==server means this endpoint sent
      it toward the server -> outbound; src==server means it came from the server
      -> inbound.
    """
    if not server_ip:
        return 'unknown'
    if role == 'fs':
        return 'inbound' if dst_ip == server_ip else 'outbound'
    return 'outbound' if dst_ip == server_ip else 'inbound'


def reconstruct_audio(packets: dict, ssrc: int, output_path: str, server_ip: str = None,
                      role: str = None) -> dict:
    """Reconstruct an audio WAV file from RTP packets for a given SSRC.
    
    Args:
        packets: RTP packets dict from extract_rtp_packets (with include_payload=True).
        ssrc: The SSRC to reconstruct.
        output_path: Path to write the output WAV file.
        server_ip: Optional server IP to determine direction.
        role: Capture point role ('seat'/'fs'/'terminal') for endpoint-relative direction.
        
    Returns:
        {
            'path': str, 'ssrc': str, 'pt': int, 'codec': str,
            'sample_rate': int, 'duration_ms': float, 'total_packets': int,
            'lost_packets': int, 'silence_filled': int, 'success': bool,
            'direction': str, 'error': str or None
        }
    """
    result = {
        'path': output_path,
        'ssrc': f'0x{ssrc:08x}',
        'pt': None,
        'codec': 'unknown',
        'sample_rate': G711_SAMPLE_RATE,
        'duration_ms': 0,
        'total_packets': 0,
        'lost_packets': 0,
        'silence_filled': 0,
        'success': False,
        'direction': 'unknown',
        'error': None,
    }
    
    # Collect packets for this SSRC, sorted by sequence number
    stream_pkts = {}
    for (k_ssrc, seq), v in packets.items():
        if k_ssrc == ssrc and len(v) >= 8:  # Has payload
            stream_pkts[seq] = v
    
    if not stream_pkts:
        result['error'] = 'No packets with payload found for this SSRC'
        return result
    
    # Determine payload type (use most common PT)
    pt_counts = defaultdict(int)
    for v in stream_pkts.values():
        pt_counts[v[2]] += 1  # v[2] is pt
    pt = max(pt_counts, key=pt_counts.get)
    result['pt'] = pt
    result['codec'] = get_pt_name(pt)
    
    # Determine direction from first packet
    first_pkt = next(iter(stream_pkts.values()))
    result['direction'] = _endpoint_direction(first_pkt[4], server_ip, role)
    
    # Check if codec is supported
    if pt not in SUPPORTED_AUDIO:
        result['error'] = f'Codec {get_pt_name(pt)} is not supported for direct reconstruction. ' \
                          f'Supported: PCMU, PCMA. Use ffmpeg for other codecs.'
        return result
    
    # Sort by sequence number
    sorted_seqs = sorted(stream_pkts.keys())
    result['total_packets'] = len(sorted_seqs)
    
    # Detect gaps and fill with silence
    all_audio = bytearray()
    prev_seq = sorted_seqs[0] - 1
    silence_frame = b'\x00' * (G711_SAMPLES_PER_PACKET * 2)  # 16-bit silence
    
    for seq in sorted_seqs:
        gap = (seq - prev_seq - 1) & 0xFFFF
        if gap > 0 and gap < 100:  # Reasonable gap (not a seq wrap)
            for _ in range(gap):
                all_audio.extend(silence_frame)
                result['silence_filled'] += 1
            result['lost_packets'] += gap
        
        raw_payload = stream_pkts[seq][7]  # Index 7 is payload bytes
        if pt == PT_PCMU:
            # μ-law to 16-bit linear PCM
            try:
                linear = audioop.ulaw2lin(raw_payload, 2)
            except Exception:
                linear = b'\x00' * (len(raw_payload) * 2)
        elif pt == PT_PCMA:
            # A-law to 16-bit linear PCM
            try:
                linear = audioop.alaw2lin(raw_payload, 2)
            except Exception:
                linear = b'\x00' * (len(raw_payload) * 2)
        else:
            linear = b'\x00' * (len(raw_payload) * 2)
        
        all_audio.extend(linear)
        prev_seq = seq
    
    # Write WAV file
    total_samples = len(all_audio) // 2
    result['duration_ms'] = (total_samples / G711_SAMPLE_RATE) * 1000
    
    try:
        with wave.open(output_path, 'w') as wf:
            wf.setnchannels(1)  # Mono
            wf.setsampwidth(2)  # 16-bit
            wf.setframerate(G711_SAMPLE_RATE)
            wf.writeframes(bytes(all_audio))
        result['success'] = True
    except Exception as e:
        result['error'] = f'Failed to write WAV file: {e}'
        return result
    
    return result


def reconstruct_video_raw(packets: dict, ssrc: int, output_path: str, server_ip: str = None,
                          role: str = None) -> dict:
    """Extract raw H.264 video stream from RTP packets with FU-A depacketization.
    
    Args:
        packets: RTP packets dict (with include_payload=True).
        ssrc: The SSRC to reconstruct.
        output_path: Path to write the raw .h264 file.
        server_ip: Optional server IP.
        role: Capture point role for endpoint-relative direction.
        
    Returns:
        {
            'path': str, 'ssrc': str, 'pt': int, 'codec': str,
            'total_packets': int, 'nal_units': int, 'fua_fragments': int,
            'success': bool, 'direction': str, 'error': str or None
        }
    """
    result = {
        'path': output_path,
        'ssrc': f'0x{ssrc:08x}',
        'pt': None,
        'codec': 'unknown',
        'total_packets': 0,
        'nal_units': 0,
        'fua_fragments': 0,
        'success': False,
        'direction': 'unknown',
        'error': None,
    }
    
    # Collect packets for this SSRC, sorted by sequence number
    stream_pkts = {}
    for (k_ssrc, seq), v in packets.items():
        if k_ssrc == ssrc and len(v) >= 8:
            stream_pkts[seq] = v
    
    if not stream_pkts:
        result['error'] = 'No packets with payload found for this SSRC'
        return result
    
    # Determine payload type
    pt_counts = defaultdict(int)
    for v in stream_pkts.values():
        pt_counts[v[2]] += 1
    pt = max(pt_counts, key=pt_counts.get)
    result['pt'] = pt
    result['codec'] = get_pt_name(pt)
    
    # Determine direction
    first_pkt = next(iter(stream_pkts.values()))
    result['direction'] = _endpoint_direction(first_pkt[4], server_ip, role)
    
    sorted_seqs = sorted(stream_pkts.keys())
    result['total_packets'] = len(sorted_seqs)
    
    # H.264 depacketization with FU-A reassembly
    # RFC 6184: NAL unit types
    NAL_TYPE_STAP_A = 24
    NAL_TYPE_FU_A = 28
    
    nal_units = []
    fua_buffer = None
    
    for seq in sorted_seqs:
        # Check if we have payload (index 7)
        if len(stream_pkts[seq]) <= 7:
            continue
        payload = stream_pkts[seq][7]
        if not payload or len(payload) < 2:
            continue
        
        nal_type = payload[0] & 0x1F
        
        if nal_type == NAL_TYPE_FU_A:
            # FU-A fragmentation unit
            result['fua_fragments'] += 1
            fu_indicator = payload[0]
            fu_header = payload[1]
            start_bit = fu_header & 0x80
            end_bit = fu_header & 0x40
            fu_nal_type = fu_header & 0x1F
            
            # Reconstruct NAL header
            nal_header = bytes([(fu_indicator & 0xE0) | fu_nal_type])
            
            if start_bit:
                # Start of a new fragmented NAL unit
                fua_buffer = bytearray(nal_header)
                fua_buffer.extend(payload[2:])
            elif fua_buffer is not None:
                fua_buffer.extend(payload[2:])
            
            if end_bit and fua_buffer is not None:
                # End of fragmented NAL unit
                nal_units.append(bytes(fua_buffer))
                fua_buffer = None
                result['nal_units'] += 1
        elif nal_type == NAL_TYPE_STAP_A:
            # STAP-A aggregation packet — extract individual NALs
            offset = 1
            while offset + 2 <= len(payload):
                nalu_size = struct.unpack('>H', payload[offset:offset + 2])[0]
                offset += 2
                if offset + nalu_size <= len(payload):
                    nal_units.append(payload[offset:offset + nalu_size])
                    result['nal_units'] += 1
                    offset += nalu_size
                else:
                    break
        elif nal_type < 24:
            # Single NAL unit packet
            nal_units.append(payload)
            result['nal_units'] += 1
        # NAL types 25-31 are reserved/unspecified, skip
    
    # Flush any remaining FU-A buffer
    if fua_buffer is not None:
        nal_units.append(bytes(fua_buffer))
        result['nal_units'] += 1
    
    if not nal_units:
        result['error'] = 'No valid NAL units extracted'
        return result
    
    # Write raw H.264 file with annex B format (start codes)
    try:
        with open(output_path, 'wb') as f:
            for nalu in nal_units:
                f.write(b'\x00\x00\x00\x01')  # Annex B start code
                f.write(nalu)
        result['success'] = True
    except Exception as e:
        result['error'] = f'Failed to write raw video: {e}'
        return result
    
    return result


def convert_video_to_mp4(raw_path: str, output_path: str) -> dict:
    """Convert raw H.264 file to MP4 using ffmpeg.
    
    Args:
        raw_path: Path to raw .h264 file.
        output_path: Path for output .mp4 file.
        
    Returns:
        {'success': bool, 'path': str, 'error': str or None}
    """
    result = {
        'success': False,
        'path': output_path,
        'error': None,
    }
    
    try:
        proc = subprocess.run(
            ['ffmpeg', '-y', '-i', raw_path, '-c', 'copy', '-f', 'mp4', output_path],
            capture_output=True, text=True, timeout=120
        )
        if proc.returncode == 0:
            result['success'] = True
        else:
            result['error'] = proc.stderr.strip()[-200:] if proc.stderr else 'ffmpeg returned non-zero'
    except FileNotFoundError:
        result['error'] = 'ffmpeg not found. Install ffmpeg to convert video.'
    except subprocess.TimeoutExpired:
        result['error'] = 'ffmpeg conversion timed out'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def generate_all_media(captures: dict, classified: dict, output_dir: str,
                       server_ip: str = None, media_types: str = 'all') -> dict:
    """Generate audio and video files from all captures.
    
    Args:
        captures: Dict of {role: rtp_data} from extract_rtp_packets (with include_payload=True).
        classified: Dict of {'audio': {ssrc: info}, 'video': {ssrc: info}}.
        output_dir: Base output directory (e.g., outputs/2026-09-11/<session_id>).
        server_ip: Detected server IP for direction identification.
        media_types: 'audio', 'video', or 'all'.
        
    Returns:
        A media manifest dict:
        {
            'audio': [{role, direction, ssrc, codec, path, url, duration_ms, ...}],
            'video': [{role, direction, ssrc, codec, path, raw_path, url, ...}],
            'unsupported': [{role, ssrc, codec, reason}],
        }
    """
    os.makedirs(output_dir, exist_ok=True)
    audio_dir = os.path.join(output_dir, 'audio')
    video_dir = os.path.join(output_dir, 'video')
    
    manifest = {
        'audio': [],
        'video': [],
        'unsupported': [],
    }
    
    roles = list(captures.keys())
    unsupported_seen = set()
    
    # Process audio streams: for each (capture file, SSRC) pair present in that
    # capture, generate a separate file. The same stream captured at different
    # points (e.g. at FS and at terminal) yields one file per capture, each
    # labeled with that capture's role and endpoint-relative direction.
    if media_types in ('audio', 'all'):
        os.makedirs(audio_dir, exist_ok=True)
        audio_streams = classified.get('audio', {})
        
        for ssrc in audio_streams:
            for role in roles:
                if ssrc not in captures[role]['streams']:
                    continue
                packets = captures[role]['packets']
                
                # Peek direction first (needed for the filename)
                direction = 'unknown'
                for (k_ssrc, seq), v in packets.items():
                    if k_ssrc == ssrc:
                        direction = _endpoint_direction(v[4], server_ip, role)
                        break
                
                filename = f"{role}_{direction}_{ssrc:08x}.wav"
                filepath = os.path.join(audio_dir, filename)
                
                audio_result = reconstruct_audio(packets, ssrc, filepath, server_ip, role)
                
                if audio_result['success']:
                    manifest['audio'].append({
                        'role': role,
                        'direction': audio_result['direction'],
                        'ssrc': audio_result['ssrc'],
                        'codec': audio_result['codec'],
                        'pt': audio_result['pt'],
                        'duration_ms': round(audio_result['duration_ms'], 1),
                        'total_packets': audio_result['total_packets'],
                        'lost_packets': audio_result['lost_packets'],
                        'path': filepath,
                        'filename': filename,
                    })
                elif audio_result['error']:
                    key = (role, audio_result['ssrc'])
                    if key not in unsupported_seen:
                        unsupported_seen.add(key)
                        manifest['unsupported'].append({
                            'role': role,
                            'ssrc': audio_result['ssrc'],
                            'codec': audio_result['codec'],
                            'reason': audio_result['error'],
                        })
    
    # Process video streams (same per-capture logic as audio)
    if media_types in ('video', 'all'):
        os.makedirs(video_dir, exist_ok=True)
        video_streams = classified.get('video', {})
        
        for ssrc in video_streams:
            for role in roles:
                if ssrc not in captures[role]['streams']:
                    continue
                packets = captures[role]['packets']
                
                direction = 'unknown'
                for (k_ssrc, seq), v in packets.items():
                    if k_ssrc == ssrc:
                        direction = _endpoint_direction(v[4], server_ip, role)
                        break
                
                raw_filename = f"{role}_{direction}_{ssrc:08x}.h264"
                raw_path = os.path.join(video_dir, raw_filename)
                
                video_result = reconstruct_video_raw(packets, ssrc, raw_path, server_ip, role)
                
                if video_result['success']:
                    # Try to convert to MP4
                    mp4_filename = f"{role}_{direction}_{ssrc:08x}.mp4"
                    mp4_path = os.path.join(video_dir, mp4_filename)
                    conv_result = convert_video_to_mp4(raw_path, mp4_path)
                    
                    video_entry = {
                        'role': role,
                        'direction': video_result['direction'],
                        'ssrc': video_result['ssrc'],
                        'codec': video_result['codec'],
                        'pt': video_result['pt'],
                        'total_packets': video_result['total_packets'],
                        'nal_units': video_result['nal_units'],
                        'fua_fragments': video_result['fua_fragments'],
                        'path': mp4_path if conv_result['success'] else raw_path,
                        'filename': mp4_filename if conv_result['success'] else raw_filename,
                        'raw_path': raw_path,
                        'raw_filename': raw_filename,
                        'mp4_available': conv_result['success'],
                        'mp4_error': conv_result.get('error') if not conv_result['success'] else None,
                    }
                    manifest['video'].append(video_entry)
                elif video_result['error']:
                    key = (role, video_result['ssrc'])
                    if key not in unsupported_seen:
                        unsupported_seen.add(key)
                        manifest['unsupported'].append({
                            'role': role,
                            'ssrc': video_result['ssrc'],
                            'codec': video_result['codec'],
                            'reason': video_result['error'],
                        })
    
    # Write manifest JSON
    manifest_path = os.path.join(output_dir, 'media_manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    
    return manifest


def get_media_urls(manifest: dict, session_id: str, output_date: str) -> dict:
    """Generate relative URLs for all media files in a manifest.
    
    Args:
        manifest: The media manifest dict.
        session_id: Session UUID.
        output_date: Date string like '2026-09-11'.
        
    Returns:
        Manifest with 'url' fields added for each media entry.
    """
    base = f'/media/{output_date}/{session_id}'
    
    for entry in manifest.get('audio', []):
        entry['url'] = f"{base}/audio/{entry['filename']}"
    
    for entry in manifest.get('video', []):
        if entry.get('mp4_available'):
            entry['url'] = f"{base}/video/{entry['filename']}"
        entry['raw_url'] = f"{base}/video/{entry['raw_filename']}"
    
    return manifest