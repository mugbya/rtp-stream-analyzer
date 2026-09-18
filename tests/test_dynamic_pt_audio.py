"""
动态载荷类型（PT 96-127）的音频识别与 OPUS 重建回归测试。

动态 PT 按媒体种类独立分配：SDP 里 audio 96=OPUS 与 video 96=H264 可以同号
并存。只看 PT 号会把 OPUS 音频误判成视频，回放区一条音频都不出现（青岛
终端抓包实测）。修复后流种类按 SDP 端口绑定 > rtpmap 单侧命中 > 实测时钟
率 > 静态 PT 表的顺序解析；OPUS 经 Ogg 封装 + ffmpeg 解码为 WAV。

Run: python3 tests/test_dynamic_pt_audio.py
"""
import os
import struct
import subprocess
import sys
import tempfile
import wave

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import numpy as np

from analyzer.stream_classifier import resolve_stream_kind, classify_all_streams
from analyzer.media_extractor import reconstruct_audio

TERMINAL, SERVER = '10.0.0.2', '10.0.0.3'


def test_sdp_port_binding_decides_kind():
    """同一 PT 96：命中 audio 宣告端口→OPUS 音频，命中 video 端口→H264 视频。"""
    port_kinds = {(TERMINAL, 56473): 'audio', (TERMINAL, 47678): 'video',
                  (SERVER, 49300): 'audio', (SERVER, 49302): 'video'}
    pt_maps = {'audio': {96: {'name': 'OPUS', 'rate': 48000}},
               'video': {96: {'name': 'H264', 'rate': 90000}}}
    kind, codec, clock = resolve_stream_kind(
        [(TERMINAL, 40000, SERVER, 49300)], {96},
        port_kinds=port_kinds, pt_maps=pt_maps)
    assert (kind, codec, clock) == ('audio', 'OPUS', 48000), (kind, codec, clock)

    kind, codec, clock = resolve_stream_kind(
        [(TERMINAL, 40002, SERVER, 49302)], {96},
        port_kinds=port_kinds, pt_maps=pt_maps)
    assert (kind, codec, clock) == ('video', 'H264', 90000), (kind, codec, clock)

    # 反方向（服务器→终端）：源端口是宣告端口同样要命中
    kind, _, _ = resolve_stream_kind(
        [(SERVER, 49300, TERMINAL, 40000)], {96},
        port_kinds=port_kinds, pt_maps=pt_maps)
    assert kind == 'audio', kind
    print("PASS: SDP port binding resolves PT 96 per media kind")


def test_rtpmap_and_clock_fallback():
    """无端口命中时：PT 两类 rtpmap 同号复用→rtpmap 无结论，靠时钟率；
    PT 只在一类 rtpmap 里→按它；无任何证据→旧口径兜底。"""
    pt_maps = {'audio': {96: {'name': 'OPUS', 'rate': 48000}},
               'video': {96: {'name': 'H264', 'rate': 90000}}}
    kind, _, _ = resolve_stream_kind(
        [(TERMINAL, 1, SERVER, 2)], {96}, pt_maps=pt_maps)
    assert kind == 'video', kind               # rtpmap 两类同号→无结论，旧口径兜底
    kind, codec, clock = resolve_stream_kind(
        [(TERMINAL, 1, SERVER, 2)], {96}, est_clock=48150.0, pt_maps=pt_maps)
    assert (kind, codec, clock) == ('audio', 'OPUS', 48000), (kind, codec, clock)
    kind, _, _ = resolve_stream_kind(
        [(TERMINAL, 1, SERVER, 2)], {96}, est_clock=90500.0, pt_maps=pt_maps)
    assert kind == 'video', kind
    # rtpmap 单侧命中：PT 只出现在 audio 侧（如 97=SPEEX）→ 音频
    kind, codec, _ = resolve_stream_kind(
        [(TERMINAL, 1, SERVER, 2)], {97},
        pt_maps={'audio': {97: {'name': 'SPEEX', 'rate': 16000}}, 'video': {}})
    assert (kind, codec) == ('audio', 'SPEEX'), (kind, codec)
    # 无任何证据时维持旧口径（96-127 视为视频），不改变无信令抓包的行为
    kind, _, _ = resolve_stream_kind([(TERMINAL, 1, SERVER, 2)], {96})
    assert kind == 'video', kind
    # 静态 PT 不受影响
    kind, codec, clock = resolve_stream_kind([(TERMINAL, 1, SERVER, 2)], {0})
    assert (kind, clock) == ('audio', 8000) and codec.startswith('PCMU'), \
        (kind, codec, clock)
    print("PASS: rtpmap / clock-rate / static-PT fallbacks")


def test_classify_all_streams_prefers_kind():
    """classify_all_streams 采用解析出的 kind，而不是把 PT 96 全归视频。"""
    streams = {
        0x100: {'count': 100, 'pt': [96], 'kind': 'audio', 'codec': 'OPUS',
                'ips': [], 'port_pairs': []},
        0x200: {'count': 100, 'pt': [96], 'kind': 'video', 'codec': 'H264',
                'ips': [], 'port_pairs': []},
    }
    cls = classify_all_streams(streams)
    assert list(cls['audio']) == [0x100], cls['audio']
    assert list(cls['video']) == [0x200], cls['video']
    print("PASS: classify_all_streams honors resolved kind")


def _demux_ogg_packets(path):
    """从 Ogg 文件取出每个完整包（测试用，只处理本测试生成的简单文件）。"""
    data = open(path, 'rb').read()
    pkts, carried = [], b''
    pos = 0
    while pos + 27 <= len(data):
        assert data[pos:pos + 4] == b'OggS'
        nseg = data[pos + 26]
        table = data[pos + 27:pos + 27 + nseg]
        body = data[pos + 27 + nseg:pos + 27 + nseg + sum(table)]
        pos += 27 + nseg + sum(table)
        off = 0
        for seg in table:
            carried += body[off:off + seg]
            off += seg
            if seg < 255:                      # 包结束
                pkts.append(carried)
                carried = b''
    # 前两包是容器头（OpusHead/OpusTags），不是音频载荷
    assert pkts[0].startswith(b'OpusHead') and pkts[1].startswith(b'OpusTags')
    return pkts[2:]


def test_reconstruct_opus_roundtrip():
    """RTP 载荷形式的 Opus 包 → reconstruct_audio → 可读 WAV（含正弦人声）。"""
    tmp = tempfile.mkdtemp()
    sine = os.path.join(tmp, 'sine.wav')
    ogg = os.path.join(tmp, 'sine.opus')
    with wave.open(sine, 'w') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(48000)
        t = np.arange(48000 * 3) / 48000.0     # 3 秒 440Hz 正弦
        wf.writeframes((np.sin(2 * np.pi * 440 * t) * 12000)
                       .astype(np.int16).tobytes())
    enc = subprocess.run(['ffmpeg', '-y', '-i', sine, '-c:a', 'libopus',
                          '-frame_duration', '20', ogg],
                         capture_output=True)
    if enc.returncode != 0:
        print("SKIP: opus encode failed (no libopus?)")
        return

    pkts = _demux_ogg_packets(ogg)
    assert len(pkts) >= 140, len(pkts)          # 3s / 20ms ≈ 150 包
    rtp = {}
    ts = 9000
    for seq, pkt in enumerate(pkts):
        rtp[(0xABCD1234, seq)] = (seq * 0.02, ts, 96, TERMINAL, SERVER, 40000, 49300, pkt)
        ts += 960
    out = os.path.join(tmp, 'out.wav')
    r = reconstruct_audio(rtp, 0xABCD1234, out, SERVER, 'terminal',
                          codec_name='OPUS')
    assert r['success'], r
    assert r['codec'] == 'OPUS' and r['pt'] == 96, r
    with wave.open(out) as wf:
        assert wf.getframerate() == 8000 and wf.getnchannels() == 1
        x = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16)
    assert abs(x.size / 8000 - 3.0) < 0.2, x.size   # 时长与源一致
    rms = float(np.sqrt((x.astype(np.float64) ** 2).mean()))
    assert rms > 1000, rms                        # 解码出的是正弦，不是静音/垃圾
    print(f"PASS: OPUS RTP payloads -> WAV ({x.size / 8000:.2f}s, rms={rms:.0f})")


def test_reconstruct_opus_with_loss():
    """seq 缺口按 granule 缺口处理：解码时长不变、缺口由解码器掩盖。"""
    tmp = tempfile.mkdtemp()
    sine = os.path.join(tmp, 'sine.wav')
    ogg = os.path.join(tmp, 'sine.opus')
    with wave.open(sine, 'w') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(48000)
        t = np.arange(48000 * 2) / 48000.0
        wf.writeframes((np.sin(2 * np.pi * 440 * t) * 12000)
                       .astype(np.int16).tobytes())
    enc = subprocess.run(['ffmpeg', '-y', '-i', sine, '-c:a', 'libopus',
                          '-frame_duration', '20', ogg], capture_output=True)
    if enc.returncode != 0:
        print("SKIP: opus encode failed")
        return
    pkts = _demux_ogg_packets(ogg)
    rtp = {}
    ts = 5000
    seq = 0
    for i, pkt in enumerate(pkts):
        if i == 50:                              # 丢 5 包（100ms）
            seq += 5
        rtp[(0xCAFE, seq)] = (i * 0.02, ts, 96, SERVER, TERMINAL, 49300, 40000, pkt)
        seq += 1
        ts += 960
    out = os.path.join(tmp, 'out.wav')
    r = reconstruct_audio(rtp, 0xCAFE, out, None, 'terminal', codec_name='OPUS')
    assert r['success'], r
    assert r['lost_packets'] == 5, r
    with wave.open(out) as wf:
        x = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16)
    assert abs(x.size / 8000 - 2.0) < 0.25, x.size
    print(f"PASS: OPUS loss handled via granule gap ({x.size / 8000:.2f}s, lost=5)")


if __name__ == '__main__':
    test_sdp_port_binding_decides_kind()
    test_rtpmap_and_clock_fallback()
    test_classify_all_streams_prefers_kind()
    test_reconstruct_opus_roundtrip()
    test_reconstruct_opus_with_loss()
    print("ALL DYNAMIC PT AUDIO TESTS PASSED")
