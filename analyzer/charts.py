"""
图表生成器
使用 matplotlib 生成分析图表。
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
from datetime import datetime
import os


# 设置中文字体
import matplotlib.font_manager as fm
_chinese_fonts = ['Heiti SC', 'STHeiti', 'SimHei', 'Arial Unicode MS', 'PingFang SC', 'DejaVu Sans']
_available = [f.name for f in fm.fontManager.ttflist]
_found = None
for _f in _chinese_fonts:
    if _f in _available:
        _found = _f
        break
if _found:
    plt.rcParams['font.sans-serif'] = [_found, 'DejaVu Sans']
    plt.rcParams['font.monospace'] = [_found, 'DejaVu Sans Mono']
else:
    plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
plt.rcParams['axes.unicode_minus'] = False

# 面向图表展示的方向/媒体类型中文名
_DIRECTION_NAMES = {
    'auto': '自动',
    'seat_to_fs': '被叫 → FS',
    'fs_to_terminal': 'FS → 主叫',
    'seat_to_terminal': '被叫 → 主叫',
    'fs_internal': 'FS 内部',
    'single_capture': '单抓包',
}
_MEDIA_NAMES = {'audio': '音频', 'video': '视频'}


def _dir_name(d):
    return _DIRECTION_NAMES.get(d, d)


def _media_name(m):
    return _MEDIA_NAMES.get(m, m)


def generate_analysis_chart(output_dir: str, analysis_data: dict) -> str:
    """生成完整的分析图表（6 合 1）。
    
    Args:
        output_dir: 输出目录
        analysis_data: 完整的分析数据字典，包含：
            - fs_delay: FS 内部延迟结果
            - cross_delays: 跨抓包延迟结果列表
            - jitter: 抖动分析结果
            - packet_loss: 丢包检测结果
            - direction: 延迟方向
            - media_type: 媒体类型 (audio/video)
            - stream_info: 流信息
            
    Returns:
        图表文件路径
    """
    fig = plt.figure(figsize=(28, 18))
    
    # 图1: FS 内部延迟时间序列
    ax1 = fig.add_subplot(3, 3, 1)
    _plot_delay_timeline(ax1, analysis_data.get('fs_delay'),
                         'FS 内部处理延迟')
    
    # 图2: 跨抓包延迟时间序列
    ax2 = fig.add_subplot(3, 3, 2)
    _plot_cross_delay_timeline(ax2, analysis_data.get('cross_delays', []))
    
    # 图3: FS 内部延迟分布直方图
    ax3 = fig.add_subplot(3, 3, 3)
    _plot_delay_histogram(ax3, analysis_data.get('fs_delay'),
                          'FS 内部延迟分布')
    
    # 图4: 包间隔（抖动）时间序列
    ax4 = fig.add_subplot(3, 3, 4)
    _plot_jitter_timeline(ax4, analysis_data.get('jitter', {}))
    
    # 图5: 包间隔分布对比
    ax5 = fig.add_subplot(3, 3, 5)
    _plot_jitter_distribution(ax5, analysis_data.get('jitter', {}))
    
    # 图6: 包旅程瀑布图
    ax6 = fig.add_subplot(3, 3, 6)
    _plot_waterfall(ax6, analysis_data.get('waterfall', []))
    
    # 图7: 丢包统计
    ax7 = fig.add_subplot(3, 3, 7)
    _plot_packet_loss(ax7, analysis_data.get('packet_loss', {}))
    
    # 图8: 延迟分段趋势
    ax8 = fig.add_subplot(3, 3, 8)
    _plot_delay_segments(ax8, analysis_data.get('fs_delay'))
    
    # 图9: 综合报告
    ax9 = fig.add_subplot(3, 3, 9)
    ax9.axis('off')
    _plot_summary_text(ax9, analysis_data)
    
    # 标题
    direction = analysis_data.get('direction', '')
    media_type = analysis_data.get('media_type', '')
    fig.suptitle(f'RTP 流分析报告\n方向: {_dir_name(direction)} | 类型: {_media_name(media_type)}',
                 fontsize=14, fontweight='bold')
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    
    # 保存
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = os.path.join(output_dir, f'analysis_{timestamp}.png')
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    
    return filepath


def _plot_delay_timeline(ax, delay_result, title):
    """绘制延迟时间序列。"""
    if not delay_result or not delay_result.get('delays'):
        ax.text(0.5, 0.5, '暂无数据', ha='center', va='center', transform=ax.transAxes)
        ax.set_title(title)
        return

    delays = delay_result['delays']
    times = [datetime.fromtimestamp(t) for t, d in delays]
    vals = [d for t, d in delays]

    ax.plot(times, vals, 'steelblue', linewidth=0.5, alpha=0.8)
    ax.axhline(y=delay_result['mean'], color='red', linestyle='--',
               label=f"均值={delay_result['mean']:.1f}ms")
    ax.axhline(y=delay_result['p95'], color='orange', linestyle='--',
               label=f"P95={delay_result['p95']:.1f}ms")
    ax.set_title(title, fontsize=10)
    ax.set_ylabel('延迟 (ms)')
    ax.legend(fontsize=7)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))


def _plot_cross_delay_timeline(ax, cross_delays):
    """绘制跨抓包延迟。"""
    if not cross_delays:
        ax.text(0.5, 0.5, '需要 2 个以上抓包\n才能计算跨抓包延迟',
                ha='center', va='center', transform=ax.transAxes, fontsize=10)
        ax.set_title('跨抓包延迟')
        return
    
    for cd in cross_delays:
        if cd.get('delays'):
            delays = cd['delays']
            times = [datetime.fromtimestamp(t) for t, d in delays]
            vals = [d for t, d in delays]
            label = cd.get('label', '')
            ax.plot(times, vals, linewidth=0.5, alpha=0.7, label=label)
    
    ax.set_title('跨抓包延迟（含时钟偏移）', fontsize=10)
    ax.set_ylabel('延迟 (ms)')
    ax.legend(fontsize=7)
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))


def _plot_delay_histogram(ax, delay_result, title):
    """绘制延迟分布直方图。"""
    if not delay_result or not delay_result.get('delays'):
        ax.text(0.5, 0.5, '暂无数据', ha='center', va='center', transform=ax.transAxes)
        ax.set_title(title)
        return

    vals = [d for t, d in delay_result['delays']]
    ax.hist(vals, bins=60, color='steelblue', edgecolor='white', alpha=0.8)
    ax.axvline(x=delay_result['mean'], color='red', linestyle='--', linewidth=2)
    ax.axvline(x=delay_result['p95'], color='orange', linestyle='--', linewidth=2)
    ax.axvline(x=delay_result['p99'], color='darkred', linestyle='--', linewidth=2)

    stat_text = (f"均值={delay_result['mean']:.1f}  P50={delay_result['p50']:.1f}  "
                 f"P95={delay_result['p95']:.1f}  P99={delay_result['p99']:.1f}  "
                 f"最大={delay_result['max']:.1f}")
    ax.set_title(f'{title}\n{stat_text}', fontsize=9)
    ax.set_xlabel('延迟 (ms)')
    ax.set_ylabel('数量')
    ax.grid(True, alpha=0.3)


def _plot_jitter_timeline(ax, jitter_data):
    """绘制抖动时间序列。"""
    if not jitter_data:
        ax.text(0.5, 0.5, '暂无抖动数据', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('RTP 包间隔（抖动）')
        return
    
    colors = ['steelblue', 'seagreen', 'purple', 'darkorange']
    for i, (label, data) in enumerate(jitter_data.items()):
        if data.get('gaps'):
            gaps = data['gaps']
            times = [datetime.fromtimestamp(t) for t, g in gaps]
            vals = [g for t, g in gaps]
            color = colors[i % len(colors)]
            ax.plot(times, vals, color=color, linewidth=0.3, alpha=0.7, label=label)
    
    ax.axhline(y=20, color='green', linestyle='--', alpha=0.5, label='理想值 20ms')
    ax.set_title('RTP 包间隔（抖动）', fontsize=10)
    ax.set_ylabel('间隔 (ms)')
    ax.legend(fontsize=6, loc='upper right')
    ax.grid(True, alpha=0.3)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))


def _plot_jitter_distribution(ax, jitter_data):
    """绘制包间隔分布对比。"""
    if not jitter_data:
        ax.text(0.5, 0.5, '暂无抖动数据', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('包间隔分布对比')
        return

    colors = ['steelblue', 'seagreen', 'purple', 'darkorange']
    for i, (label, data) in enumerate(jitter_data.items()):
        if data.get('gaps'):
            vals = [g for t, g in data['gaps']]
            color = colors[i % len(colors)]
            ax.hist(vals, bins=40, range=(0, 60), color=color, edgecolor='white',
                    alpha=0.5, label=f"{label}（均值 {data['mean']:.1f}ms）")

    ax.axvline(x=20, color='green', linestyle='--', linewidth=2, label='参考线 20ms')
    ax.set_title('包间隔分布', fontsize=10)
    ax.set_xlabel('间隔 (ms)')
    ax.set_ylabel('数量')
    ax.legend(fontsize=7)
    ax.grid(True, alpha=0.3)


def _plot_waterfall(ax, waterfall_data):
    """绘制包旅程瀑布图。"""
    if not waterfall_data:
        ax.text(0.5, 0.5, '需要 3 个以上抓包\n才能绘制包旅程瀑布图',
                ha='center', va='center', transform=ax.transAxes, fontsize=10)
        ax.set_title('包旅程瀑布图')
        return

    colors = ['steelblue', 'orange', 'green', 'red']
    labels = waterfall_data.get('labels', [])
    segments = waterfall_data.get('segments', [])

    if not segments:
        ax.text(0.5, 0.5, '暂无瀑布图数据', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('包旅程瀑布图')
        return
    
    base_time = segments[0][0][0] if segments and segments[0] else 0
    n_packets = min(len(segments), 30)
    
    for i in range(n_packets):
        for j, (t, label) in enumerate(zip(segments[i], labels)):
            if j < len(colors):
                ax.barh(i, 0.4, left=t - base_time, height=0.5, 
                       color=colors[j % len(colors)], alpha=0.8)
    
    from matplotlib.patches import Patch
    legend_patches = [Patch(color=colors[i], label=labels[i]) 
                      for i in range(min(len(labels), len(colors)))]
    ax.legend(handles=legend_patches, fontsize=7, loc='lower right')
    ax.set_title(f'包旅程（前 {n_packets} 包）', fontsize=10)
    ax.set_xlabel('距首包时间 (s)')
    ax.set_ylabel('包序号')
    ax.grid(True, alpha=0.3)


def _plot_packet_loss(ax, loss_data):
    """绘制丢包统计。"""
    if not loss_data:
        ax.text(0.5, 0.5, '暂无丢包数据', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('丢包统计')
        return

    ax.axis('off')
    text = "丢包统计\n" + "="*30 + "\n\n"
    for ssrc, data in loss_data.items():
        label = data.get('label', f'SSRC=0x{ssrc:08x}')
        status = '✓ 无丢包' if data['is_clean'] else '✗ 有丢包'
        text += (f"{label}:\n"
                 f"  包数: {data['total_packets']}  "
                 f"丢失: {data['total_lost']}  "
                 f"丢包率: {data['loss_rate_pct']:.2f}%  {status}\n\n")
    
    ax.text(0.05, 0.95, text, transform=ax.transAxes, fontsize=8,
            verticalalignment='top', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))


def _plot_delay_segments(ax, delay_result):
    """绘制延迟分段趋势（检测缓冲堆积）。"""
    if not delay_result or not delay_result.get('delays') or len(delay_result['delays']) < 10:
        ax.text(0.5, 0.5, '数据不足', ha='center', va='center', transform=ax.transAxes)
        ax.set_title('延迟分段趋势（缓冲堆积检查）')
        return
    
    delays = delay_result['delays']
    n = len(delays)
    segments = 5
    chunk_size = n // segments
    
    chunk_means = []
    chunk_labels = []
    for i in range(segments):
        start = i * chunk_size
        end = start + chunk_size if i < segments - 1 else n
        chunk_vals = [d[1] for d in delays[start:end]]
        chunk_means.append(np.mean(chunk_vals))
        t = datetime.fromtimestamp(delays[start][0])
        chunk_labels.append(t.strftime('%H:%M:%S'))
    
    x = range(len(chunk_means))
    ax.bar(x, chunk_means, color='steelblue', alpha=0.7)
    ax.axhline(y=delay_result['mean'], color='red', linestyle='--', label=f"均值={delay_result['mean']:.1f}ms")
    ax.set_xticks(x)
    ax.set_xticklabels(chunk_labels, rotation=45, fontsize=7)
    ax.set_title('延迟分段趋势（5 段）——检查缓冲堆积', fontsize=10)
    ax.set_ylabel('平均延迟 (ms)')
    ax.legend(fontsize=7)
    ax.grid(True, alpha=0.3)

    # 检测趋势
    if len(chunk_means) >= 2:
        trend = chunk_means[-1] - chunk_means[0]
        if abs(trend) > 10:
            direction = '上升' if trend > 0 else '下降'
            ax.text(0.5, 0.95, f'⚠ 趋势：{direction}（{trend:+.1f}ms）',
                    transform=ax.transAxes, ha='center', fontsize=9, color='red')


def _plot_summary_text(ax, analysis_data):
    """绘制综合报告文本。"""
    ax.axis('off')
    
    direction = analysis_data.get('direction', '')
    media_type = analysis_data.get('media_type', '')
    fs_delay = analysis_data.get('fs_delay', {})
    clock_info = analysis_data.get('clock_info', {})

    text = f"""========================================
    RTP 分析报告
    方向: {_dir_name(direction)}
    媒体类型: {_media_name(media_type)}
========================================

FS 内部延迟:
"""
    if fs_delay and fs_delay.get('count', 0) > 0:
        text += (f"  均值: {fs_delay['mean']:.1f}ms  "
                 f"P50: {fs_delay['p50']:.1f}ms\n"
                 f"  P95: {fs_delay['p95']:.1f}ms  "
                 f"P99: {fs_delay['p99']:.1f}ms\n"
                 f"  最大: {fs_delay['max']:.1f}ms  "
                 f"标准差: {fs_delay['std']:.1f}ms\n"
                 f"  尖峰(>50ms): {fs_delay['outliers_50ms']}  "
                 f"(>100ms): {fs_delay['outliers_100ms']}\n")
    else:
        text += "  （需要 FS 抓包才能分析此项）\n"

    if clock_info.get('warning'):
        text += f"\n⚠ {clock_info['warning']}\n"

    text += "\n说明:\n"
    text += "  跨抓包延迟包含抓包机间的时钟偏移。\n"
    text += "  FS 内部延迟在同一台机器上测量，不受时钟影响。\n"
    text += "  局域网内网络传输延迟通常 < 2ms。\n"

    # 结论
    text += "\n结论:\n"
    if fs_delay and fs_delay.get('count', 0) > 0:
        if fs_delay['mean'] < 20 and fs_delay['p95'] < 50:
            text += "  ✓ FS 处理延迟健康（< 20ms）。\n"
            text += "    若仍感知延迟，请检查：\n"
            text += "      - 终端抖动缓冲设置\n"
            text += "      - 音频设备 / 编码器缓冲\n"
            text += "      - 应用层缓冲\n"
        elif fs_delay['mean'] < 50:
            text += "  ⚠ FS 处理延迟可接受，但偏高。\n"
        else:
            text += "  ✗ FS 处理延迟过高！\n"
            text += "    请检查 FS 配置与负载。\n"
    
    ax.text(0.05, 0.98, text, transform=ax.transAxes, fontsize=7,
            verticalalignment='top', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))