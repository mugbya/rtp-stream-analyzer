"""
Media Extractor
Reconstruct audio and video from RTP packet payloads.
"""
import os
import json
import struct
import wave
import audioop
import base64
import binascii
import re
import subprocess
from datetime import datetime
from collections import defaultdict

from analyzer.stream_classifier import AUDIO_PT, VIDEO_PT_RANGE, get_pt_name, identify_direction
from analyzer.ts_continuity import signed32

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

# OPUS：RTP 载荷就是 Opus 包本身（RFC 7587），ffmpeg 不能直接读裸 Opus 包，
# 需要先封成 Ogg Opus 容器再交给 ffmpeg 解码。RTP 时钟固定 48kHz。
OPUS_CLOCK = 48000


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


# ---------- Ogg Opus 封装（供 ffmpeg 解码 RTP 里的 OPUS 音频） ----------

def _ogg_crc32(data: bytes) -> int:
    """Ogg 页校验：CRC-32 多项式 0x04c11db7，MSB 先行，初值 0，无终值取反。"""
    crc = 0
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else crc << 1
            crc &= 0xFFFFFFFF
    return crc


def _ogg_page(serial: int, seq: int, granule: int, header_type: int,
              pkts: list) -> bytes:
    """把一组完整包封成一个 Ogg 页（调用方保证段表 ≤255 项）。"""
    segments = []
    for pkt in pkts:
        full, rem = divmod(len(pkt), 255)
        segments.extend([255] * full)
        segments.append(rem)
    body = b''.join(pkts)
    header = (b'OggS' + bytes([0, header_type])
              + struct.pack('<qII', granule, serial, seq)
              + b'\x00\x00\x00\x00'          # CRC 占位
              + bytes([len(segments)]) + bytes(segments))
    crc = _ogg_crc32(header + body)
    header = header[:22] + struct.pack('<I', crc) + header[26:]
    return header + body


def _write_ogg_opus(stream_pkts: dict, pt: int, path: str) -> dict:
    """按 seq 顺序把 RTP 载荷封装成 Ogg Opus 文件。

    丢包（seq 缺口）与 DTX 静音不插入占位包：granule 按 RTP 时间戳推进，
    缺口对解码器表现为"该时间段没有包"，libopus 会做 PLC 掩盖，时长保持
    与真实通话一致。时间戳倒退（发送端重置）时按单包时长前推，保证 granule
    单调（Ogg 要求）。

    Returns {'packets': int, 'lost_packets': int, 'spp': int}，spp 为单包
    采样数（48kHz 时钟）。
    """
    seqs = sorted(stream_pkts)
    ts_list = [stream_pkts[s][1] for s in seqs]
    deltas = [signed32(b - a) for a, b in zip(ts_list, ts_list[1:])]
    positive = sorted(d for d in deltas if d > 0)
    spp = positive[len(positive) // 2] if positive else 960
    if not (0 < spp <= OPUS_CLOCK):     # 单包不超过 1s，异常时间戳回退 20ms
        spp = 960

    base_ts = stream_pkts[seqs[0]][1]
    serial = 0x524152  # 任意固定 serial，单流文件无需唯一
    pages = []
    buf, buf_segments, page_seq = [], 0, 0

    def _flush(granule, header_type):
        nonlocal buf, buf_segments, page_seq
        if not buf:
            return
        pages.append(_ogg_page(serial, page_seq, granule, header_type, buf))
        page_seq += 1
        buf, buf_segments = [], 0

    def _add(pkt, granule, last):
        nonlocal buf, buf_segments
        segs = len(pkt) // 255 + 1
        if buf_segments + segs > 255:
            _flush(prev_granule[0], 0)
        buf.append(pkt)
        buf_segments += segs
        if last:
            _flush(granule, 0x04)   # EOS

    # ID 头（OpusHead）+ 注释头（OpusTags）：各占一个 BOS 起始页
    id_header = (b'OpusHead' + bytes([1, 1])
                 + struct.pack('<H', 0)             # pre-skip
                 + struct.pack('<I', OPUS_CLOCK)    # 输入采样率（信息性）
                 + struct.pack('<h', 0)             # output gain
                 + bytes([0]))                      # mapping family
    comment_header = b'OpusTags' + struct.pack('<I', 0) + struct.pack('<I', 0)
    pages.append(_ogg_page(serial, page_seq, 0, 0x02, [id_header]))
    page_seq += 1
    pages.append(_ogg_page(serial, page_seq, 0, 0x00, [comment_header]))
    page_seq += 1

    prev_granule = [0]
    prev_seq = seqs[0] - 1
    lost = 0
    for i, seq in enumerate(seqs):
        gap = (seq - prev_seq - 1) & 0xFFFF
        if 0 < gap < 100:
            lost += gap
        ts = stream_pkts[seq][1]
        granule = max(prev_granule[0], signed32(ts - base_ts) + spp)
        payload = stream_pkts[seq][7]
        # 非主 PT 包（如 RFC 4733 DTMF）不是 Opus 包，跳过（granule 缺口由 PLC 补）
        if payload and stream_pkts[seq][2] == pt:
            _add(payload, granule, i == len(seqs) - 1)
            prev_granule[0] = granule
        prev_seq = seq
    if buf:
        _flush(prev_granule[0], 0x04)   # 末包是非主 PT 被跳过时也要收尾

    with open(path, 'wb') as f:
        f.write(b''.join(pages))
    return {'packets': len(seqs) - lost, 'lost_packets': lost, 'spp': spp}


def _decode_opus_to_wav(ogg_path: str, wav_path: str) -> dict:
    """用 ffmpeg 把 Ogg Opus 解码成 8kHz 单声道 WAV（与 G.711 重建同规格）。"""
    result = {'success': False, 'error': None}
    try:
        proc = subprocess.run(
            ['ffmpeg', '-y', '-i', ogg_path, '-ac', '1', '-ar', '8000',
             '-f', 'wav', wav_path],
            capture_output=True, text=True, timeout=300)
        if proc.returncode == 0:
            result['success'] = True
        else:
            result['error'] = (proc.stderr.strip()[-200:]
                               if proc.stderr else 'ffmpeg returned non-zero')
    except FileNotFoundError:
        result['error'] = 'OPUS 音频需要 ffmpeg 解码（未检测到 ffmpeg）'
    except subprocess.TimeoutExpired:
        result['error'] = 'ffmpeg 解码超时'
    except Exception as e:
        result['error'] = str(e)
    return result


def _reconstruct_opus_audio(stream_pkts: dict, pt: int, result: dict) -> dict:
    """OPUS 流的音频重建：RTP 载荷 → Ogg Opus → ffmpeg → 8kHz WAV。

    result 为 reconstruct_audio 初始化好的骨架，就地补全后返回。
    """
    seqs = sorted(stream_pkts)
    result['total_packets'] = len(seqs)
    ogg_path = result['path'] + '.tmp.opus'
    try:
        info = _write_ogg_opus(stream_pkts, pt, ogg_path)
        result['samples_per_packet'] = info['spp']
        result['packet_duration_ms'] = round(info['spp'] / OPUS_CLOCK * 1000, 1)
        result['lost_packets'] = info['lost_packets']
        result['silence_filled'] = info['lost_packets']
        dec = _decode_opus_to_wav(ogg_path, result['path'])
        if not dec['success']:
            result['error'] = dec['error']
            return result
        with wave.open(result['path']) as wf:
            frames = wf.getnframes()
        result['duration_ms'] = round(frames / G711_SAMPLE_RATE * 1000, 1)
        result['success'] = True
        return result
    finally:
        try:
            os.remove(ogg_path)
        except OSError:
            pass


def reconstruct_audio(packets: dict, ssrc: int, output_path: str, server_ip: str = None,
                      role: str = None, codec_name: str = None) -> dict:
    """Reconstruct an audio WAV file from RTP packets for a given SSRC.

    Args:
        packets: RTP packets dict from extract_rtp_packets (with include_payload=True).
        ssrc: The SSRC to reconstruct.
        output_path: Path to write the output WAV file.
        server_ip: Optional server IP to determine direction.
        role: Capture point role ('seat'/'fs'/'terminal') for endpoint-relative direction.
        codec_name: SDP rtpmap 解析出的编码名（动态 PT 只看号码判不出编码，
            如 OPUS@96）；None 时按静态 PT 表取名。

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
        'samples_per_packet': G711_SAMPLES_PER_PACKET,
        'packet_duration_ms': 20.0,
        'ts_gap_filled': 0,
        'ts_extra_silence_ms': 0.0,
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
    result['codec'] = codec_name or get_pt_name(pt)

    # Determine direction from first packet
    first_pkt = next(iter(stream_pkts.values()))
    result['direction'] = _endpoint_direction(first_pkt[4], server_ip, role)

    # Check if codec is supported
    is_opus = (result['codec'] or '').upper().startswith('OPUS')
    if pt not in SUPPORTED_AUDIO and not is_opus:
        result['error'] = f'Codec {result["codec"]} is not supported for direct reconstruction. ' \
                          f'Supported: PCMU, PCMA, OPUS. Use ffmpeg for other codecs.'
        return result

    if is_opus:
        return _reconstruct_opus_audio(stream_pkts, pt, result)
    
    # Sort by sequence number
    sorted_seqs = sorted(stream_pkts.keys())
    result['total_packets'] = len(sorted_seqs)

    # 每包媒体时长以 RTP 时间戳实测为准（设备包化不一定是 20ms/160 样本，
    # 30ms/240 等同样常见；时间戳增量在 8kHz 时钟下即样本数）
    ts_list = [stream_pkts[s][1] for s in sorted_seqs]
    deltas = [signed32(b - a) for a, b in zip(ts_list, ts_list[1:])]
    positive = sorted(d for d in deltas if d > 0)
    spp = positive[len(positive) // 2] if positive else 0
    if not (0 < spp <= G711_SAMPLE_RATE // 2):  # 单包不超过半秒，否则视为异常时间戳
        spp = G711_SAMPLES_PER_PACKET
    result['samples_per_packet'] = spp
    result['packet_duration_ms'] = round(spp / G711_SAMPLE_RATE * 1000, 1)

    # Detect gaps and fill with silence
    all_audio = bytearray()
    prev_seq = sorted_seqs[0] - 1
    prev_ts = None
    ts_gap_filled = 0
    ts_extra_silence_ms = 0.0

    for seq in sorted_seqs:
        ts = stream_pkts[seq][1]
        gap = (seq - prev_seq - 1) & 0xFFFF
        expected_advance = spp
        if gap > 0 and gap < 100:  # Reasonable gap (not a seq wrap)
            expected_advance = (gap + 1) * spp
            all_audio.extend(b'\x00' * (gap * spp * 2))
            result['silence_filled'] += gap
            result['lost_packets'] += gap

        # 时间戳缺口：seq 连续但媒体时间断档（静音抑制/时间戳跳变）时，
        # 按 ts 实测缺口补静音，否则重建音频会比真实通话短
        if prev_ts is not None:
            excess = signed32(ts - prev_ts) - expected_advance
            if spp > 0 and excess > spp // 2:
                if excess <= G711_SAMPLE_RATE * 5:  # 超过 5s 视为时间戳重置，不补
                    all_audio.extend(b'\x00' * (excess * 2))
                    ts_gap_filled += 1
                    ts_extra_silence_ms += excess / G711_SAMPLE_RATE * 1000
                else:
                    ts_gap_filled += 1

        raw_payload = stream_pkts[seq][7]  # Index 7 is payload bytes
        if stream_pkts[seq][2] != pt:
            # 非 main PT 包（如 RFC 4733 DTMF telephone-event，载荷仅 4 字节
            # 事件描述）不能按主 PT 解码——按原样解会产出垃圾采样，听感为
            # 轻微咔哒；置零，时间线由上方 ts 缺口补偿逻辑对齐
            linear = b'\x00' * (len(raw_payload) * 2)
        elif pt == PT_PCMU:
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
        prev_ts = ts

    result['ts_gap_filled'] = ts_gap_filled
    result['ts_extra_silence_ms'] = round(ts_extra_silence_ms, 1)
    
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
                       server_ip: str = None, media_types: str = 'all',
                       ssrc_filter=None, call_id: str = None) -> dict:
    """Generate audio and video files from all captures.

    Args:
        captures: Dict of {role: rtp_data} from extract_rtp_packets (with include_payload=True).
        classified: Dict of {'audio': {ssrc: info}, 'video': {ssrc: info}}.
        output_dir: Base output directory (e.g., outputs/2026-09-11/<session_id>).
        server_ip: Detected server IP for direction identification.
        media_types: 'audio', 'video', or 'all'.
        ssrc_filter: Optional set of SSRCs; only these streams are rebuilt
            (used to limit media to one detected call).
        call_id: Optional call identifier stamped into manifest entries.
        
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
        'call_id': call_id,
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
            if ssrc_filter is not None and ssrc not in ssrc_filter:
                continue
            # SDP rtpmap 解析出的编码名：动态 PT（如 OPUS@96）只看 PT 号
            # 识别不出编码，重建与展示都靠它
            codec_name = (audio_streams.get(ssrc) or {}).get('codec')
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

                audio_result = reconstruct_audio(packets, ssrc, filepath,
                                                 server_ip, role,
                                                 codec_name=codec_name)
                
                if audio_result['success']:
                    manifest['audio'].append({
                        'call_id': call_id,
                        'role': role,
                        'direction': audio_result['direction'],
                        'ssrc': audio_result['ssrc'],
                        'codec': audio_result['codec'],
                        'pt': audio_result['pt'],
                        'duration_ms': round(audio_result['duration_ms'], 1),
                        'total_packets': audio_result['total_packets'],
                        'lost_packets': audio_result['lost_packets'],
                        'packet_duration_ms': audio_result.get('packet_duration_ms'),
                        'ts_gap_filled': audio_result.get('ts_gap_filled', 0),
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
            if ssrc_filter is not None and ssrc not in ssrc_filter:
                continue
            codec_name = (video_streams.get(ssrc) or {}).get('codec')
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
                        'call_id': call_id,
                        'role': role,
                        'direction': video_result['direction'],
                        'ssrc': video_result['ssrc'],
                        'codec': codec_name or video_result['codec'],
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


# ---------- 媒体流「谁到谁」标注 ----------
# 回放页每条媒体文件只有「呼入/呼出」（相对抓包点的收发方向），FS 端一次
# 列出多条流时无法分辨哪条属于主叫腿、哪条属于被叫腿。这里从流所属通话的
# SIP 信令识别主叫/被叫，结合每条流的实际收发 IP 生成标注。

# 兜底角色短名：无 SIP 信令可依时，抓包点自己的 IP（非服务器）用此称呼。
# FS 抓包里的其他 IP 无法区分坐席/终端，不命名，直接显示原始 IP
_PARTY_ROLE_NAMES = {'seat': '被叫端（坐席）', 'terminal': '主叫端（终端）', 'fs': 'FS'}


# base64 形态的 SIP 身份 token（平台/话机把号码编码成 base64 当分机号）
_B64_TOKEN_RE = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')


def _decode_ident_tokens(label: str) -> str:
    """解出身份串里 base64 token 的可读内容（"Extension LTU4NT..." 里的号码），
    解不出（非法 base64 或含不可打印字符）保持原样。"""
    def _dec(m):
        tok = m.group(0)
        try:
            raw = base64.b64decode(tok + '=' * (-len(tok) % 4), validate=True)
            txt = raw.decode('ascii')
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return tok
        return txt if all(32 <= ord(ch) < 127 for ch in txt) else tok
    return _B64_TOKEN_RE.sub(_dec, label)


def _ident_label(ident: dict) -> str:
    """SIP From/To 头的可读称呼：'张三（1002）' / '1002' / 显示名。

    话机自报的超长单 token（base64 设备串等，From 的显示名与 user 常是同
    一串）没有可读性，不采用——端点由展示层以 IP 标注。
    """
    if not ident:
        return ''
    name = (ident.get('name') or '').strip()
    user = (ident.get('user') or '').strip()
    if name and user and name != user and user not in name:
        label = f'{name}（{user}）'
    else:
        label = name or user
    label = _decode_ident_tokens(label)
    if len(label) > 20 and ' ' not in label:
        return ''
    return label


def extract_call_parties(call: dict, server_ip: str = None) -> dict:
    """从一通通话的信令流程里识别主叫/被叫的 IP 与身份。

    判定口径与前端 SIP 阶梯图一致：
    - 主叫 = 第一个非服务器侧发出的 INVITE 的源，身份取其 From 头（UAC
      自报身份）；
    - 被叫 = INVITE 事务 200 OK 的非服务器发送方，身份取呼向它的 INVITE
      的 To 头——响应回显请求的 From，不能用作被叫身份。

    Returns:
        {'caller_ip', 'caller_ident', 'answerer_ip', 'answerer_ident'}，
        信令缺失时对应项为 None / 空 dict。
    """
    flow = call.get('sip_flow') or []
    inv = next((m for m in flow if m['method'] == 'INVITE'
                and m.get('src') != server_ip), None)
    if inv is None:
        inv = next((m for m in flow if m.get('kind') == 'request'), None)
    if inv is None:
        inv = flow[0] if flow else None
    caller_ip = inv.get('src') if inv else None
    caller_ident = (inv.get('from') or {}) if inv else {}

    ok = next((m for m in flow if m['method'] == '200'
               and m.get('cseq_method') == 'INVITE'
               and m.get('src') != server_ip), None)
    answerer_ip = ok.get('src') if ok else None
    if answerer_ip is None:
        # 未接通的通话（CANCEL/486/480/487 收场）没有 INVITE 的 200 OK：被叫
        # 退而取信令里出现最多的非服务器对端（与前端阶梯图同口径），保证被
        # 叫侧标注不丢
        peers = {}
        for m in flow:
            for ip in (m.get('src'), m.get('dst')):
                if ip and ip != server_ip and ip != caller_ip:
                    peers[ip] = peers.get(ip, 0) + 1
        if peers:
            answerer_ip = max(peers, key=peers.get)
    answerer_ident = {}
    if answerer_ip:
        # 呼向被叫的 INVITE 的 To；抓不到时退回 200 OK 的 To（回显同一头）
        inv_to = next((m for m in flow if m['method'] == 'INVITE'
                       and m.get('dst') == answerer_ip
                       and _ident_label(m.get('to') or {})), None)
        if inv_to is None:
            inv_to = next((m for m in flow if m.get('dst') == answerer_ip
                           and _ident_label(m.get('to') or {})), None)
        answerer_ident = (inv_to.get('to') if inv_to else None) or (ok.get('to') or {})

    return {'caller_ip': caller_ip, 'caller_ident': caller_ident,
            'answerer_ip': answerer_ip, 'answerer_ident': answerer_ident}


def _party_label(ip: str, parties: dict, server_ip: str, role_names: dict) -> str:
    """端点 IP 的称呼：SIP 主叫/被叫身份 > 抓包角色名 > 原始 IP。"""
    if parties:
        if ip and ip == parties.get('caller_ip'):
            ident = _ident_label(parties.get('caller_ident'))
            return f'主叫 {ident}' if ident else '主叫'
        if ip and ip == parties.get('answerer_ip'):
            ident = _ident_label(parties.get('answerer_ident'))
            return f'被叫 {ident}' if ident else '被叫'
    if server_ip and ip == server_ip:
        return 'FS'
    if ip in role_names:
        return role_names[ip]
    return ip or ''


def _party_chain(parties: dict, server_ip: str):
    """通话拓扑行：主叫 ↔ FS ↔ 被叫（各端称呼 + IP），无信令时为 None。"""
    if not parties or not (parties.get('caller_ip') or parties.get('answerer_ip')):
        return None
    label = lambda ip: _party_label(ip, parties, server_ip, {})
    caller = ({'label': label(parties['caller_ip']), 'ip': parties['caller_ip']}
              if parties.get('caller_ip') else None)
    answerer = ({'label': label(parties['answerer_ip']), 'ip': parties['answerer_ip']}
                if parties.get('answerer_ip') else None)
    return {'caller': caller, 'answerer': answerer, 'server_ip': server_ip}


def describe_media_parties(manifest: dict, captures: dict, calls: list,
                           server_ip: str = None, files_info: list = None) -> dict:
    """给媒体清单里的每条流标注收发双方（谁到谁），就地修改并返回。

    每条媒体文件（audio/video/unsupported）写入结构化标注：

        entry['flow'] = {'from': {'label', 'ip'}, 'to': {'label', 'ip'}}

    from/to 是媒体的真实发送/接收方：呼入 = 对端 → 本抓包点，呼出反之。
    同时在 manifest['parties'] 汇总本批媒体涉及的通话拓扑（主叫 ↔ FS ↔
    被叫，含 IP），供回放区开头一句话描述。

    Args:
        manifest: generate_all_media 的输出。
        captures: {role: rtp_data}，只需其中的 streams（含 port_pairs）。
        calls: detect_calls 的 API 结果列表（含 ssrcs / sip_flow），
            用于把 SSRC 归属到通话并提取主叫/被叫。
        server_ip: 检测到的服务器 IP。
        files_info: 上传文件信息（role + ips），用于无信令时的角色名兜底。
    """
    role_names = {}
    for fi in files_info or []:
        role = fi.get('role')
        if role == 'fs':
            continue
        for ip in fi.get('ips') or []:
            if ip != server_ip:
                role_names.setdefault(ip, _PARTY_ROLE_NAMES.get(role, role))

    call_of_ssrc = {}
    for call in calls or []:
        for ssrc in call.get('ssrcs') or []:
            call_of_ssrc.setdefault(ssrc, call)

    parties_by_call = {}

    def _parties(call):
        if call is None:
            return None
        key = call.get('call_id')
        if key not in parties_by_call:
            parties_by_call[key] = extract_call_parties(call, server_ip)
        return parties_by_call[key]

    def _label_entry(entry):
        try:
            ssrc = int(entry.get('ssrc', ''), 16)
        except ValueError:
            return
        role = entry.get('role')
        stream_meta = (captures.get(role) or {}).get('streams', {}).get(ssrc) or {}
        port_pairs = stream_meta.get('port_pairs') or []
        if not port_pairs:
            return
        parties = _parties(call_of_ssrc.get(ssrc))
        # 媒体包的真实流向就是 src → dst（呼入 = 对端 → 本抓包点，呼出反之）
        src_ip, dst_ip = port_pairs[0][0], port_pairs[0][2]
        entry['flow'] = {
            'from': {'label': _party_label(src_ip, parties, server_ip, role_names),
                     'ip': src_ip},
            'to': {'label': _party_label(dst_ip, parties, server_ip, role_names),
                   'ip': dst_ip},
        }

    for kind in ('audio', 'video', 'unsupported'):
        for entry in manifest.get(kind) or []:
            _label_entry(entry)

    # 拓扑汇总：只覆盖实际出现在回放里的媒体对应的通话，按主被叫去重
    chains, seen = [], set()
    for kind in ('audio', 'video'):
        for entry in manifest.get(kind) or []:
            try:
                ssrc = int(entry.get('ssrc', ''), 16)
            except ValueError:
                continue
            chain = _party_chain(_parties(call_of_ssrc.get(ssrc)), server_ip)
            if not chain:
                continue
            key = (chain['caller']['ip'] if chain['caller'] else None,
                   chain['answerer']['ip'] if chain['answerer'] else None)
            if key not in seen:
                seen.add(key)
                chains.append(chain)
    manifest['parties'] = chains
    return manifest