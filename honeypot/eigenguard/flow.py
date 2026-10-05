"""Turns a list of timestamped packet events into flow-level features.

The feature names follow the CIC-IDS2017 convention so the output can be
compared against published CIC results. The values are computed from packets
actually observed on the connection, not estimated.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

Direction = str  # "fwd" (client -> honeypot) or "bwd" (honeypot -> client)


@dataclass
class FlowMetrics:
    """Flow-level summary of one connection."""

    duration_seconds: float = 0.0
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_length_fwd_packets: int = 0
    total_length_bwd_packets: int = 0

    flow_bytes_per_second: float = 0.0
    flow_packets_per_second: float = 0.0

    fwd_packet_length_max: float = 0.0
    fwd_packet_length_mean: float = 0.0
    fwd_packet_length_std: float = 0.0
    fwd_packet_length_min: float = 0.0

    bwd_packet_length_max: float = 0.0
    bwd_packet_length_mean: float = 0.0
    bwd_packet_length_std: float = 0.0
    bwd_packet_length_min: float = 0.0

    flow_iat_mean: float = 0.0
    flow_iat_std: float = 0.0
    flow_iat_max: float = 0.0
    flow_iat_min: float = 0.0

    fwd_iat_mean: float = 0.0
    fwd_iat_std: float = 0.0
    fwd_iat_max: float = 0.0

    bwd_iat_mean: float = 0.0
    bwd_iat_std: float = 0.0
    bwd_iat_max: float = 0.0

    down_up_ratio: float = 0.0
    average_packet_size: float = 0.0
    avg_fwd_segment_size: float = 0.0
    avg_bwd_segment_size: float = 0.0

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def _stats(values: List[float]) -> Tuple[float, float, float, float]:
    """Return (mean, std, max, min) for a list, all zero when empty."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    if len(values) == 1:
        return float(values[0]), 0.0, float(values[0]), float(values[0])
    mean = statistics.fmean(values)
    std = statistics.stdev(values)
    return float(mean), float(std), float(max(values)), float(min(values))


def _iat(timestamps: List[float]) -> Tuple[float, float, float, float]:
    """Inter-arrival times between consecutive packets of one direction."""
    if len(timestamps) < 2:
        return 0.0, 0.0, 0.0, 0.0
    deltas = [
        timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
    ]
    return _stats(deltas)


@dataclass
class PacketRecorder:
    """Accumulates (timestamp, size) events, then computes flow metrics."""

    events: List[Tuple[float, Direction, int]] = field(default_factory=list)

    def record(self, timestamp: float, direction: Direction, size: int) -> None:
        if size <= 0:
            return
        self.events.append((timestamp, direction, int(size)))

    @property
    def total_bytes(self) -> int:
        return sum(size for _, _, size in self.events)

    def compute(
        self, started_at: Optional[float] = None, ended_at: Optional[float] = None
    ) -> FlowMetrics:
        if not self.events:
            return FlowMetrics(duration_seconds=0.0)

        events = sorted(self.events, key=lambda item: item[0])
        first_ts = started_at if started_at is not None else events[0][0]
        last_ts = ended_at if ended_at is not None else events[-1][0]

        # A zero-length window would otherwise produce a division by zero.
        duration = last_ts - first_ts
        if duration <= 0:
            duration = 1e-6

        fwd_lengths: List[float] = []
        bwd_lengths: List[float] = []
        all_ts: List[float] = []
        fwd_ts: List[float] = []
        bwd_ts: List[float] = []

        for ts, direction, size in events:
            all_ts.append(ts)
            if direction == "fwd":
                fwd_lengths.append(float(size))
                fwd_ts.append(ts)
            else:
                bwd_lengths.append(float(size))
                bwd_ts.append(ts)

        fwd_bytes = int(sum(fwd_lengths))
        bwd_bytes = int(sum(bwd_lengths))
        total_packets = len(fwd_lengths) + len(bwd_lengths)
        total_bytes = fwd_bytes + bwd_bytes

        flow_mean, flow_std, flow_max, flow_min = _iat(all_ts)
        fwd_mean_iat, fwd_std_iat, fwd_max_iat, _ = _iat(fwd_ts)
        bwd_mean_iat, bwd_std_iat, bwd_max_iat, _ = _iat(bwd_ts)

        f_len_mean, f_len_std, f_len_max, f_len_min = _stats(fwd_lengths)
        b_len_mean, b_len_std, b_len_max, b_len_min = _stats(bwd_lengths)

        return FlowMetrics(
            duration_seconds=duration,
            total_fwd_packets=len(fwd_lengths),
            total_bwd_packets=len(bwd_lengths),
            total_length_fwd_packets=fwd_bytes,
            total_length_bwd_packets=bwd_bytes,
            flow_bytes_per_second=total_bytes / duration,
            flow_packets_per_second=total_packets / duration,
            fwd_packet_length_max=f_len_max,
            fwd_packet_length_mean=f_len_mean,
            fwd_packet_length_std=f_len_std,
            fwd_packet_length_min=f_len_min,
            bwd_packet_length_max=b_len_max,
            bwd_packet_length_mean=b_len_mean,
            bwd_packet_length_std=b_len_std,
            bwd_packet_length_min=b_len_min,
            flow_iat_mean=flow_mean,
            flow_iat_std=flow_std,
            flow_iat_max=flow_max,
            flow_iat_min=flow_min,
            fwd_iat_mean=fwd_mean_iat,
            fwd_iat_std=fwd_std_iat,
            fwd_iat_max=fwd_max_iat,
            bwd_iat_mean=bwd_mean_iat,
            bwd_iat_std=bwd_std_iat,
            bwd_iat_max=bwd_max_iat,
            down_up_ratio=(len(bwd_lengths) / len(fwd_lengths)) if fwd_lengths else 0.0,
            average_packet_size=(total_bytes / total_packets) if total_packets else 0.0,
            avg_fwd_segment_size=f_len_mean,
            avg_bwd_segment_size=b_len_mean,
        )