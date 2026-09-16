"""
声音问题分类：把各检测器的原始结论翻译成"用户听得懂的问题种类"。

对照 docs/《声音问题种类.md》清单（类别 / 用户听感词 / 工程术语 /
常见原因 / 验证方法 / P0~P3 优先级），并补充清单里没有、但抓包分析必需
的一个维度——**可观测性**：清单里的问题有些在 RTP 层能直接确认（单通、
丢包、时钟异常、啸叫、削波），有些只能间接推断（窄带发闷 → 可能是蓝牙
HFP），有些本质是声学/设备侧现象、抓包层面看不到（风噪、喷麦、齿音、
接触不良、侧音回声、双讲），只能给出人工验证方法。诚实区分这三类，
避免"检测不到 = 没问题"的误导。

classify_problems() 与 reporter 消费同一份分析结果，把各检测器命中的
证据按问题种类聚合：一个种类一条输出，附证据、用户听感词、排查方向与
验证方法。同一问题被多个检测器命中（如丢包同时被序号缺口、RTCP RR
自报发现）时合并为同一类下的多条证据，而不是重复报成多个问题。

清单表格本身没有标注每行的可观测性与优先级归属，代码里以 TAXONOMY
（可观测部分，含优先级）/ UNOBSERVABLE（抓包看不到的部分）两个表落位；
若后续修订 md 清单，两处需同步。

视频问题的同构实现见 video_problem_taxonomy（对照 docs/《视频问题.md》）。
"""
import re

from .stream_classifier import AUDIO_PT, VIDEO_PT_RANGE

# 证据严重级 → 展示排序
_SEVERITY_RANK = {'critical': 0, 'warning': 1, 'info': 2}
_PRIORITY_RANK = {'P0': 0, 'P1': 1, 'P2': 2, 'P3': 3}

# 键形态兼容：int SSRC、'0x…' 十六进制串、'fs (SSRC=0x…)' 展示标签
_SSRC_RE = re.compile(r'0x([0-9a-fA-F]+)')


def _ssrc_int_of(key) -> int | None:
    """从结果字典的键里取 SSRC 整数（兼容 int / 十六进制串 / 展示标签）。"""
    if isinstance(key, int):
        return key
    m = _SSRC_RE.search(str(key))
    return int(m.group(1), 16) if m else None


def stream_media_kind(results: dict, key) -> str:
    """判定一个结果键（SSRC）属于 audio 还是 video。

    按 classified_streams 的分桶归属判别（{'audio': {ssrc: info}, …}）；
    老会话数据缺 classified_streams 时回退 audio（保持旧版只按音频理解
    的口径），unknown 桶同样按 audio 处理。
    """
    ssrc = _ssrc_int_of(key)
    classified = results.get('classified_streams') or {}
    if ssrc is not None:
        if ssrc in (classified.get('video') or {}):
            return 'video'
        if ssrc in (classified.get('audio') or {}):
            return 'audio'
    return 'audio'

# 各检测器 issue kind → 问题种类 id（仅音画质量分析器的 kinds；报告层
# 其余结论按下方各自的字段直接判定，不走 kind 路由）
_KIND_TO_PROBLEM = {
    'rtp_loss': 'loss_artifact',
    'howling': 'howling',
    'hum': 'buzz',
    'clipping': 'clipping',
    'clicks': 'transient_noise',
    'noise': 'noise_floor',
    'low_level': 'low_volume',
    'high_level': 'high_volume',
    # rtp_order 拆到 clock_anomaly / dup_audio，按 rtp_integrity 字段区分
    # rtp_ok 是正常项，不进分类
}

# 丢包/断音类的优先级随严重度浮动（清单：严重断续 P1，机器人音/吞字 P2）
_PRIORITY_BY_SEVERITY = {
    'loss_artifact': {'critical': 'P1', 'warning': 'P2', 'info': 'P2'},
    'dropouts': {'critical': 'P1', 'warning': 'P2', 'info': 'P3'},
    'latency': {'critical': 'P1', 'warning': 'P2', 'info': 'P3'},
}

# 抓包可直接观测/推断的问题种类。feel=用户听感词（清单"用户常说"列），
# description=种类描述，causes=常见原因/先查方向，verify=验证方法。
TAXONOMY = {
    'one_way_audio': {
        'name': '单通 / 无声',
        'category': '无声 / 连通',
        'term': 'One-way audio / No audio after connect',
        'priority': 'P0',
        'feel': ['我听不到对方', '对方听不到我', '接通了但没声音'],
        'description': '通话已经建立，但某个方向（或两个方向）的声音没有到达。'
                       '抓包里表现为该方向的 RTP 流整段缺失、或流存在但始终无人声。',
        'causes': ['媒体没经过 FS 转发（bypass / SDP 改道）', 'NAT / 防火墙拦断 RTP',
                   '终端静音、音频焦点或路由错误', '发声端确实没有送出人声'],
        'verify': ['看各端上/下行 RTP 是否齐全（本报告"无声诊断"逐腿判定）',
                   '对比信令里宣告的媒体地址与实际收发地址', '换终端 / 切外放对比'],
    },
    'loss_artifact': {
        'name': '丢包失真（电音 / 机关枪 / 吞字）',
        'category': '失真 / 断续',
        'term': 'Packet loss / PLC artifact',
        'priority': 'P2',
        'feel': ['电音', '机器人音', '机关枪声', '爆音后静音', '吞字、丢字'],
        'description': 'RTP 序号缺口=网络丢了包，播放端只能用 PLC 掩盖或补静音，'
                       '丢得集中就出现电音/机关枪声，丢在字上就是吞字。',
        'causes': ['网络拥塞或无线信号弱', '抖动缓冲不足导致的主动丢包', '链路 QoS 未保障'],
        'verify': ['抓包看丢包率与突发分布（本报告丢包/时间戳区块）',
                   'RTCP RR 的 fraction lost 交叉印证', '换网络环境对比'],
    },
    'dropouts': {
        'name': '断音 / 内容缺失',
        'category': '断续',
        'term': 'Dropout / Media gap',
        'priority': 'P2',
        'feel': ['说话一顿一顿', '突然没声了又恢复', '吞字'],
        'description': '发送端媒体时钟出现大段跳变——两包之间少了一段声音。'
                       '对方静音时属于静音抑制的正常省流量；说话时出现则是真缺失。',
        'causes': ['发送端采集/编码停顿', '静音抑制误判（把人声当静音）',
                   '发送端 CPU 过载'],
        'verify': ['对照回放音频听断点位置', '关 VAD/静音抑制对比', '看断点是否落在说话段'],
    },
    'clock_anomaly': {
        'name': '时钟异常（变调 / 忽快忽慢）',
        'category': '协议 / 时钟',
        'term': 'Clock drift / Timestamp backward',
        'priority': 'P2',
        'feel': ['声音变调', '忽快忽慢', '快进感'],
        'description': 'RTP 时间戳是发送端给声音盖的媒体时钟标记，正常一路增大；'
                       '倒退说明发送端时钟异常，按序号重排的播放会错位，产生变调与节奏乱。',
        'causes': ['发送端时钟/采样率异常', '虚拟机或软终端时钟漂移', '重采样配置错误'],
        'verify': ['看时间戳倒退包的捕获时间是否集中（本报告时间戳区块）',
                   '换终端或关闭虚拟化音频设备对比'],
    },
    'dup_audio': {
        'name': '重复音',
        'category': '断续',
        'term': 'Duplicate / Stuck timestamp',
        'priority': 'P2',
        'feel': ['同一个字重复两遍', '卡住又继续'],
        'description': '序号前进但媒体时间原地踏步——发送端时钟停走或冗余重传，'
                       '同一段声音被播了两遍。',
        'causes': ['发送端时钟短暂停走', 'RTP 冗余重传配置', '抓包点重复收录（多抓包合并）'],
        'verify': ['对照回放音频确认重复感', '单看某一端抓包排除合并重复'],
    },
    'howling': {
        'name': '啸叫 / 持续单频音',
        'category': '回声 / 设备',
        'term': 'Howling / Feedback',
        'priority': 'P1',
        'feel': ['尖啸声', '刺耳的嘀嘀声', '一直响的单音'],
        'description': '频谱上出现"又高又窄又稳定"的谱峰并持续——典型为扬声器'
                       '回授啸叫（外放+麦克风近距离）或单音提示音串入通话。',
        'causes': ['免提外放音量过大、麦距太近', 'AEC 失效', '提示音/彩铃串入媒体流'],
        'verify': ['戴耳机或切手机听筒对比是否消失', '调低外放音量', '检查终端 AEC 开关'],
    },
    'clipping': {
        'name': '削波破音',
        'category': '失真',
        'term': 'Clipping / Overload',
        'priority': 'P2',
        'feel': ['破音', '炸麦', '沙哑、噼啪'],
        'description': '波形顶端被削平（连续大幅值采样一字排开）——发话端增益'
                       '过高把信号削顶，听感沙哑刺耳。',
        'causes': ['麦克风增益/发送音量过高', '说话人贴麦太近', 'AGC 上限配置不当'],
        'verify': ['调低发送增益后复测', '看本报告削波事件时间与说话段对齐情况'],
    },
    'buzz': {
        'name': '低频嗡声 / 电流声',
        'category': '噪声',
        'term': 'Hum / Buzz / Ground loop',
        'priority': 'P2',
        'feel': ['嗡嗡声', '滋滋电流声', '低频呜呜声'],
        'description': '能量集中在低频段（50/100Hz 及其倍频附近）且持续存在——'
                       '典型为电源干扰、接地环路或设备风扇声串入采集。',
        'causes': ['电源/接地问题', '音频线与电源线并行', '设备风扇进拾音'],
        'verify': ['换电源/换 USB 口对比', '拔掉不必要的外设再看是否消失'],
    },
    'transient_noise': {
        'name': '瞬态咔哒 / 爆点',
        'category': '噪声',
        'term': 'Transient noise / Click',
        'priority': 'P2',
        'feel': ['咔哒声', '噼啪声', '敲击声'],
        'description': '孤立的脉冲尖峰（幅度极大、前后邻域都很小）——突发电气'
                       '干扰、设备切换或线路接触的瞬间打火。',
        'causes': ['电气干扰', '设备热插拔/切换', '线路接触不良（与"一动就断"相关）'],
        'verify': ['对照回放听爆点节奏是否与操作/移动相关', '换线材/换接口对比'],
    },
    'noise_floor': {
        'name': '底噪偏高',
        'category': '噪声',
        'term': 'Noise floor',
        'priority': 'P3',
        'feel': ['沙沙的底噪', '背景一直有声音', '电流麦'],
        'description': '静音段（无人说话时）的电平中位数偏高——拾音环境噪声或'
                       '设备自噪声会一直传给对方。',
        'causes': ['环境嘈杂', '麦克风增益过高放大自噪声', '降噪（ANS）未开或过弱'],
        'verify': ['换安静环境复测', '开关 ANS 对比', '看底噪是持续平稳还是随环境变化'],
    },
    'low_volume': {
        'name': '音量偏低',
        'category': '音量',
        'term': 'Low signal level',
        'priority': 'P2',
        'feel': ['声音小', '发虚', '听不清'],
        'description': '话音平均电平低于正常范围——不是杂音，但对方会觉得声音小、'
                       '发虚，常与"听不清"投诉相关。',
        'causes': ['麦克风增益/发送音量低', '麦被遮挡或距离远', 'AGC 未生效'],
        'verify': ['调高发送增益复测', '录音自测电平', '检查 AGC 配置'],
    },
    'high_volume': {
        'name': '音量偏高（易破音）',
        'category': '音量',
        'term': 'High signal level',
        'priority': 'P3',
        'feel': ['声音太冲', '大点声就炸'],
        'description': '话音平均电平接近满幅——再大一点就会削波破音，是削波类'
                       '投诉的前兆。',
        'causes': ['发送增益过高', 'AGC 目标电平设置过高'],
        'verify': ['调低发送增益', '与削波检测的命中时间互相印证'],
    },
    'latency': {
        'name': '延迟 / 抖动偏大',
        'category': '网络',
        'term': 'Latency / Jitter',
        'priority': 'P2',
        'feel': ['延迟大', '接话慢', '声音时快时慢', '像对讲机'],
        'description': '包传输或处理耗时偏大、包到达间隔不稳。延迟大到一定程度'
                       '双方容易抢话，抖动大则播放缓冲压力大、加剧断续。',
        'causes': ['网络拥塞/绕路', 'FS 处理或转码开销', '抖动缓冲过大', '蓝牙链路附加延迟'],
        'verify': ['看分段延迟链路定位哪一段慢（本报告延迟区块）',
                   'RTT/jitter 统计交叉印证', '换有线网络对比'],
    },
    'narrowband': {
        'name': '窄带编码（发闷 / 水声）',
        'category': '设备 / 编解码',
        'term': 'Narrowband codec / Possible HFP',
        'priority': 'P3',
        'feel': ['声音发闷', '像隔了层水', '像老式电话', '蓝牙通话质感'],
        'description': '全链路落在 8kHz 窄带编码（如 G.711）：3.4kHz 以上频段'
                       '没有声音，高频细节先天缺失。这不是故障，是编码能力上限；'
                       '若终端走蓝牙，很可能是 HFP/SCO 窄带链路。',
        'causes': ['协商只落到 G.711 窄带', '蓝牙 HFP/SCO 链路', 'FS 转码到窄带'],
        'verify': ['查 SDP 协商的编码与时钟率（本报告信令区块）',
                   '终端切 A2DP / 宽带编码（Opus）对比', '确认 FS 是否参与转码'],
    },
}

# 抓包层面无法直接确认的听感问题（清单里有、抓包测不到或不可靠），只给
# 出人工验证方法，避免"没报出来 = 没问题"的误导。
UNOBSERVABLE = [
    {'name': '风噪', 'category': '噪声', 'feel': ['呼呼的风声', '噗噗声'],
     'why': '抓包只有编码后的字节流，无法区分"风吹麦克风"与一般环境噪声',
     'verify': '户外/遮挡测试，换麦克风位置'},
    {'name': '呼吸声 / 喷麦', 'category': '噪声', 'feel': ['呼气声很大', '噗——的喷麦声'],
     'why': '近讲话学现象，谱形与人声重叠，抓包层无法判别',
     'verify': '近讲测试，加防喷罩或开高通滤波（HPF）'},
    {'name': '齿音刺耳', 'category': '噪声', 'feel': ['咝咝声刺耳'],
     'why': '高频增益/EQ 问题，8k 窄带编码下高频已被截掉、抓包看不出来',
     'verify': '录齿音对比，调高频 EQ'},
    {'name': '忽大忽小（AGC 抽吸）', 'category': '音量', 'feel': ['声音一阵大一阵小'],
     'why': 'AGC 动态行为需要电平波动统计，当前检测器暂未覆盖（可后续加入）',
     'verify': '关 AGC 对比，看是否消失'},
    {'name': '一动就断（接触不良）', 'category': '断续', 'feel': ['动一下线就没声'],
     'why': '表现为整段流消失/长缺口，抓包无法与网络中断区分（FS 转发判定能排除转发侧）',
     'verify': '摇动线材/接头测试，换线对比'},
    {'name': '听到自己延迟（侧音/回声）', 'category': '回声', 'feel': ['听到自己的回声', '自己被延迟播放'],
     'why': '需要上/下行音频相关性分析才能确认（可后续版本加入），单看时序不可靠',
     'verify': '关侧音/AEC 对比，戴耳机确认是否消失'},
    {'name': '双讲压制（半双工）', 'category': '双讲', 'feel': ['我一说话对方就断', '同时说话只剩一边'],
     'why': 'AEC/降噪的双讲行为在单端抓包里无法与"对方本来就没说话"区分',
     'verify': '双讲测试（双方同时说话），关 3A 对比'},
    {'name': '特定 App 音频会话异常', 'category': '平台', 'feel': ['某个软件里才有问题'],
     'why': '音频焦点/路由是终端操作系统行为，抓包不经过终端应用层',
     'verify': '换 App 对比，查该 App 的音频权限与 SDK 版本'},
]

# 抓包里完全无声但"正常"的情况说明，避免把静音抑制误读成问题
_NO_PROBLEM_NOTE = '以上未命中的听感问题不代表不存在——声学与设备侧现象抓包看不到，见"无法仅凭抓包确认"列表。'


def _gap_human(gap_ms: float) -> str:
    """把累计媒体时间缺口换成人类可读单位（与 reporter 口径一致）。"""
    if gap_ms >= 60000:
        return f'{gap_ms / 60000:.1f} 分钟'
    if gap_ms >= 1000:
        return f'{gap_ms / 1000:.1f} 秒'
    return f'{gap_ms:.0f} 毫秒'


class _Collector:
    """按问题 id 聚合证据；同一问题被多个检测器命中时合并为多条证据。

    taxonomy 缺省用音频清单，视频分类器传入 VIDEO_TAXONOMY 复用；
    priority_by_severity 是"优先级随严重度浮动"的映射，缺省用音频表，
    视频分类器传入自己的映射。
    """

    def __init__(self, taxonomy: dict | None = None,
                 priority_by_severity: dict | None = None):
        self.taxonomy = taxonomy or TAXONOMY
        self.priority_by_severity = priority_by_severity or _PRIORITY_BY_SEVERITY
        self.found = {}

    def add(self, pid: str, evidence: str, severity: str = 'info',
            source: str = ''):
        if severity not in _SEVERITY_RANK:
            severity = 'info'
        entry = self.found.setdefault(pid, {'evidence': [], 'sources': [],
                                            'severity': 'info'})
        if evidence not in entry['evidence']:
            entry['evidence'].append(evidence)
        if source and source not in entry['sources']:
            entry['sources'].append(source)
        if _SEVERITY_RANK[severity] < _SEVERITY_RANK[entry['severity']]:
            entry['severity'] = severity

    def output(self) -> list:
        """按优先级 → 严重度输出问题条目（每种类的固定字段取自分类表）。"""
        problems = []
        for pid, hit in self.found.items():
            spec = self.taxonomy[pid]
            severity = hit['severity']
            priority = (self.priority_by_severity.get(pid, {})
                        .get(severity, spec['priority']))
            problems.append({
                'id': pid,
                'name': spec['name'],
                'category': spec['category'],
                'term': spec['term'],
                'priority': priority,
                'severity': severity,
                'feel': spec['feel'],
                'description': spec['description'],
                'evidence': hit['evidence'][:10],
                'sources': hit['sources'],
                'causes': spec['causes'],
                'verify': spec['verify'],
            })
        problems.sort(key=lambda p: (_PRIORITY_RANK[p['priority']],
                                     _SEVERITY_RANK[p['severity']], p['id']))
        return problems


def classify_problems(results: dict) -> dict:
    """把分析结果归类到《声音问题种类》清单，输出面向用户的分类报告。

    Returns:
        {'available': 是否适用（有音频流且做过分析）,
         'problems': [...按优先级排序的问题条目],
         'unobservable': [...抓包看不到的听感问题与人工验证方法],
         'summary': 一句话总结,
         'notes': [判定边界说明]}
    """
    notes = []
    has_audio = False
    col = _Collector()

    # —— 无声诊断：单通 / 无声（P0） ——
    audio_health = results.get('audio_health') or {}
    if audio_health.get('available'):
        has_audio = True
        for d in audio_health.get('directions', []):
            v = d.get('verdict')
            if v in ('blocked', 'no_source', 'silent_source'):
                col.add('one_way_audio', f"{d.get('label', '')}：{d.get('verdict_text', '')}",
                        'critical', '无声诊断')
            elif v == 'silent_path':
                col.add('one_way_audio', f"{d.get('label', '')}：{d.get('verdict_text', '')}",
                        'warning', '无声诊断')
    elif results.get('audio_health') is not None:
        notes.append('无声诊断不可用（未选中通话或缺对应抓包点），单通/无声'
                     '只能靠流存在性间接判断')

    # —— FS 媒体转发判定：改道 / 无上行同样是单通形态 ——
    fs_relay = results.get('fs_relay') or {}
    if fs_relay.get('available'):
        v = fs_relay.get('verdict')
        if v in ('redirected', 'no_relay'):
            col.add('one_way_audio', f"FS 媒体转发：{fs_relay.get('headline', '')}",
                    'critical', 'FS 转发判定')
        elif v == 'partial_uplink':
            col.add('one_way_audio', f"FS 媒体转发：{fs_relay.get('headline', '')}",
                    'warning', 'FS 转发判定')

    # —— 流级丢包（只认音频流；视频流丢包归视频分类器） ——
    for key, data in (results.get('packet_loss') or {}).items():
        if stream_media_kind(results, key) == 'video':
            continue
        if data.get('is_clean', True):
            continue
        has_audio = True
        sev = 'critical' if data.get('loss_rate_pct', 0) >= 3 else 'warning'
        col.add('loss_artifact',
                f"{data.get('label', '')}: 丢失 {data.get('total_lost', 0)} 包"
                f"（丢包率 {data.get('loss_rate_pct', 0):.2f}%）",
                sev, '丢包检测')

    # —— RTCP RR 自报丢包（接收端亲历视角；kind 缺省按音频，旧数据兼容） ——
    for label, entry in (results.get('rtcp') or {}).items():
        if entry.get('kind') == 'video':
            continue
        rr = entry.get('rr')
        if not rr:
            continue
        lost_pct = rr.get('fraction_lost_pct') or 0
        if lost_pct > 2:
            has_audio = True
            col.add('loss_artifact',
                    f"{label}: 接收端 RTCP RR 自报丢包 {lost_pct}%"
                    f"（累计 {rr.get('cum_lost', 0)} 包）",
                    'warning', 'RTCP')

    # —— 音画质量分析（DSP 检测 + RTP 秩序） ——
    for label, q in (results.get('audio_quality') or {}).items():
        has_audio = True
        integ = q.get('rtp_integrity') or {}
        if integ.get('ts_backward'):
            col.add('clock_anomaly',
                    f"{label}: RTP 时间戳倒退 {integ['ts_backward']} 处"
                    f"——发送端时钟异常，播放重排会变调、忽快忽慢",
                    'critical', '音画质量')
        if integ.get('ts_duplicate'):
            col.add('dup_audio',
                    f"{label}: RTP 时间戳重复 {integ['ts_duplicate']} 处"
                    f"——同一段声音会被播两遍",
                    'warning', '音画质量')
        for issue in q.get('issues') or []:
            pid = _KIND_TO_PROBLEM.get(issue.get('kind'))
            if pid:
                col.add(pid, f"{label}: {issue.get('message', '')}",
                        issue.get('severity', 'info'), '音画质量')
        if q.get('decodable'):
            codec = q.get('codec', '')
            if 'PCMU' in codec or 'PCMA' in codec or 'G.711' in codec:
                col.add('narrowband',
                        f"{label}: 编码为 {codec}（8kHz 窄带），3.4kHz 以上"
                        f"频段没有声音——听感发闷属编码特性，若走蓝牙则很可能是"
                        f"HFP/SCO 链路",
                        'info', '编码检查')

    # —— 时间戳连续性（发送端媒体时钟行为；frame 模式是视频流，跳过） ——
    for label, data in (results.get('ts_continuity') or {}).items():
        if data.get('mode') == 'frame':
            continue
        gap = data.get('total_media_gap_ms') or 0
        if data.get('jump_count', 0):
            has_audio = True
            if gap >= 300:
                sev = 'critical'
            elif gap >= 50:
                sev = 'warning'
            else:
                sev = 'info'
            col.add('dropouts',
                    f"{label}: 声音内容断开 {data['jump_count']} 处，"
                    f"累计缺少约 {_gap_human(gap)}的声音"
                    + ('（含静音抑制的正常缺口，断点落在说话段才是问题）'
                       if gap >= 50 else '（量很小，基本无感）'),
                    sev, '时间戳连续性')
        if data.get('backward_count', 0):
            has_audio = True
            col.add('clock_anomaly',
                    f"{label}: 声音时间往回走 {data['backward_count']} 处"
                    f"（发送端时钟异常）",
                    'critical', '时间戳连续性')
        if data.get('duplicate_count', 0):
            has_audio = True
            col.add('dup_audio',
                    f"{label}: 同一时刻声音重复 {data['duplicate_count']} 处",
                    'warning', '时间戳连续性')

    # —— 延迟 / 抖动 ——
    fs_delay = results.get('fs_delay') or {}
    if fs_delay.get('count', 0) > 0:
        if fs_delay.get('mean', 0) >= 50:
            col.add('latency',
                    f"FS 内部处理延迟均值 {fs_delay['mean']:.1f}ms"
                    f"（P95 {fs_delay.get('p95', 0):.1f}ms），明显偏高",
                    'critical', '延迟分析')
        elif fs_delay.get('mean', 0) >= 20:
            col.add('latency',
                    f"FS 内部处理延迟均值 {fs_delay['mean']:.1f}ms，偏高",
                    'warning', '延迟分析')
    for label, data in (results.get('jitter') or {}).items():
        if stream_media_kind(results, label) == 'video':
            continue
        if data.get('std', 0) > 10:
            has_audio = True
            col.add('latency',
                    f"{label}: 包间隔抖动偏大（标准差 {data['std']:.1f}ms）"
                    f"——播放缓冲压力大，会加剧断续",
                    'warning', '抖动分析')
    delay_chains = results.get('delay_chains') or {}
    if delay_chains.get('available'):
        for d in delay_chains.get('directions', []):
            if d.get('verdict') == 'high':
                col.add('latency',
                        f"延迟链路·{d.get('label', '')}: {d.get('verdict_text', '')}",
                        'warning', '延迟链路')
        for r in delay_chains.get('roundtrip', []):
            if r.get('status') == 'high':
                col.add('latency',
                        f"延迟链路·{r.get('pair', '')}: 往返 {r.get('ms', 0)}ms，"
                        f"链路整体偏慢",
                        'warning', '延迟链路')

    # —— 适用范围与说明 ——
    if results.get('media_type') == 'video':
        notes.append('本次仅分析了视频流，声音问题分类不适用')
    if results.get('checks') and results.get('checks', {}).get('quality') is False:
        notes.append('未勾选音画质量分析，啸叫/削波/底噪等杂音类问题本次未检测')
    if not has_audio and not col.found:
        notes.append('分析结果中没有音频流的检测数据，无法做声音问题分类')

    problems = col.output()
    # summary 只统计真正的问题（warning/critical）；info 级条目（如窄带编码
    # 特性说明）是解释性信息，不参与"发现问题"的计数，避免正常 G.711 通话
    # 被总结成"检出问题"
    real = [p for p in problems if p['severity'] != 'info']
    if real:
        worst = real[0]
        summary = (f"检出 {len(real)} 类声音问题，最需要先处理的是 "
                   f"{worst['priority']}·{worst['name']}（{worst['category']}）")
    elif problems:
        summary = '抓包层面未发现可归类的声音问题（下方 info 级条目为编码特性说明，不是故障）'
    else:
        summary = ('抓包层面未发现可归类的声音问题' if has_audio
                   else '没有音频流检测数据，声音问题分类不可用')

    return {
        'available': has_audio or bool(problems),
        'problems': problems,
        'unobservable': UNOBSERVABLE,
        'summary': summary,
        'notes': notes + ([_NO_PROBLEM_NOTE] if problems else []),
    }
