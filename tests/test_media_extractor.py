"""
Unit test for media_extractor: non-main-PT packets (RFC 4733 DTMF events)
must become silence placeholders, not garbage decoded as G.711.

Run: python3 tests/test_media_extractor.py
"""
import os
import sys
import tempfile
import wave

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import numpy as np

from analyzer.media_extractor import reconstruct_audio

SSRC = 0xABCD


def test_event_packet_payload_zeroed():
    """DTMF 事件包（4 字节载荷）不得按主 PT 解码成垃圾采样：置零、时间线不变。"""
    packets = {}
    t, ts = 0.0, 1000
    for i in range(3):
        packets[(SSRC, i)] = (t, ts, 0, '10.0.0.2', '10.0.0.1', 5000, 6000,
                              b'\xd5' * 160)          # μ-law 静音
        t += 0.02
        ts += 160
    packets[(SSRC, 3)] = (t, ts, 101, '10.0.0.2', '10.0.0.1', 5000, 6000,
                          b'\xff' * 4)                # 事件载荷，解码会是大幅值
    out = os.path.join(tempfile.mkdtemp(), 'out.wav')
    r = reconstruct_audio(packets, SSRC, out)
    assert r['success'], r
    with wave.open(out) as wf:
        x = np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.int16)
    assert x.size == 3 * 160 + 4, x.size            # 时间线仍按包推进，不受影响
    assert int(np.abs(x[480:]).max()) == 0, x[480:] # 事件载荷为静音，而非垃圾采样
    print("PASS: DTMF event payload decoded as silence, timeline unchanged")


if __name__ == '__main__':
    test_event_packet_payload_zeroed()
    print("ALL MEDIA EXTRACTOR TESTS PASSED")
