#!/usr/bin/env python3
"""
iperf3 Datacruncher Tool
-------------------------
This script processes multiple iperf3 JSON output files (generated with the -J flag)
to extract throughput and RTT data. It then produces two comparison plots:
  - Throughput (Mbps) vs. Time (s): split into forward and reverse tests.
  - RTT (ms) vs. Time (s): a single plot that overlays all RTT curves.

Usage:
  python3 utils/iperf_datacruncher.py <json_files> [--out-dir <output_directory>]

The generated plots are saved in the specified output directory.
"""

import json
import os
import argparse
import re
import matplotlib.pyplot as plt


def extract_throughput(intervals):
    """
    Extract mid-times and throughput (Mbps) from iperf3 intervals.

    :param intervals: List of interval dictionaries from the iperf3 JSON.
    :return: (times, throughput) where:
        - times is a list of midpoints of each interval (in seconds)
        - throughput is a list of throughput values in Mbps
    """
    times = []
    throughput = []
    for interval in intervals:
        sum_data = interval.get("sum", {})
        start = sum_data.get("start", 0)
        end = sum_data.get("end", 0)
        mid = (start + end) / 2
        times.append(mid)
        # Convert bits_per_second to Mbps
        bps = sum_data.get("bits_per_second", 0)
        throughput.append(bps / 1e6)
    return times, throughput


def extract_rtt(intervals):
    """
    Extract mid-times and average RTT (ms) from iperf3 intervals.

    :param intervals: List of interval dictionaries from the iperf3 JSON.
    :return: (times, rtts) where:
        - times is a list of midpoints of each interval (in seconds)
        - rtts is a list of average RTT values (in milliseconds)
    """
    times = []
    rtts = []
    for interval in intervals:
        stream_rtts = [
            stream["rtt"] for stream in interval.get("streams", []) if "rtt" in stream
        ]
        avg_rtt = sum(stream_rtts) / len(stream_rtts) if stream_rtts else None
        sum_data = interval.get("sum", {})
        start = sum_data.get("start", 0)
        end = sum_data.get("end", 0)
        mid = (start + end) / 2
        times.append(mid)
        # Convert rtt from microseconds to milliseconds
        if avg_rtt is not None:
            avg_rtt_ms = avg_rtt / 1000.0
        else:
            avg_rtt_ms = None
        rtts.append(avg_rtt_ms)
    return times, rtts


def label_from_filename(filepath):
    """
    Derive a label from the filename. For baseline and tunneled tests, it labels as before.
    For tests with 'parallel' in the filename, it extracts the connection count from the filename.
    The final label includes the test type, connection count (if applicable) and direction
    (Forward/Reverse).

    :param filepath: Full path to the JSON file.
    :return: A string label describing the test (e.g. "Baseline Forward",
             "Tunneled (parallel, 10) Reverse", etc.)
    """
    base = os.path.basename(filepath)
    if "baseline" in base:
        label = "Baseline"
    elif "tunneled_client_parallel" in base:
        # Look for the connection count after 'parallel' (optionally after '_R')
        # Examples: iperf3_tunneled_client_parallel_10.json or iperf3_tunneled_client_parallel_R_10.json
        match = re.search(r"parallel(?:_R)?_(\d+)", base)
        if match:
            count = match.group(1)
            label = f"Tunneled (parallel, {count})"
        else:
            label = "Tunneled (parallel)"
    elif "tunneled_client" in base:
        label = "Tunneled"
    else:
        label = base

    if "_R" in base:
        label += " Reverse"
    else:
        label += " Forward"
    return label


def load_data(json_file):
    """
    Load a JSON file and extract throughput and RTT data.

    :param json_file: Path to the iperf3 JSON file.
    :return: (t_th, throughput, t_rtt, rtt) where:
        - t_th: list of time points for throughput
        - throughput: list of throughput values (Mbps)
        - t_rtt: list of time points for RTT
        - rtt: list of RTT values (ms)
      or None if there's an error or no intervals.
    """
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading {json_file}: {e}")
        return None

    intervals = data.get("intervals", [])
    if not intervals:
        print(f"No interval data in {json_file}")
        return None

    t_th, throughput = extract_throughput(intervals)
    t_rtt, rtt = extract_rtt(intervals)
    return t_th, throughput, t_rtt, rtt


def main():
    """
    Main entry point for the script:
      1. Parse arguments
      2. Load JSON data
      3. Plot throughput comparisons (Forward vs Reverse)
      4. Plot RTT comparisons (all in one plot)
    """
    parser = argparse.ArgumentParser(
        description="Compare iperf3 throughput and RTT across multiple JSON files."
    )
    parser.add_argument("json_files", nargs="+", help="Path(s) to iperf3 JSON file(s).")
    parser.add_argument(
        "--out-dir", default="testplots", help="Directory to save plot images."
    )
    args = parser.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    # Group throughput curves by direction
    forward_throughput = []
    reverse_throughput = []
    # For RTT, collect all curves in a single list
    all_rtt = []

    # Load data from each JSON file and categorize it
    for json_file in args.json_files:
        data = load_data(json_file)
        if data is None:
            continue
        t_th, throughput, t_rtt, rtt = data
        label = label_from_filename(json_file)

        if "Reverse" in label:
            reverse_throughput.append((label, t_th, throughput))
        else:
            forward_throughput.append((label, t_th, throughput))

        all_rtt.append((label, t_rtt, rtt))

    # ----- Throughput Comparison Plot -----
    fig, (ax_fwd, ax_rev) = plt.subplots(1, 2, figsize=(14, 6), sharey=True)
    fig.suptitle("iperf3 Throughput Comparison (Mbps)", fontsize=16)

    # Forward
    if forward_throughput:
        for label, t, th in forward_throughput:
            ax_fwd.plot(t, th, marker="o", markersize=6, alpha=0.9, label=label)
        ax_fwd.set_title("Forward")
        ax_fwd.set_xlabel("Time (s)")
        ax_fwd.set_ylabel("Throughput (Mbps)")
        ax_fwd.grid(True)
        ax_fwd.legend()
        # Force x=0 and y=0 to appear
        ax_fwd.set_xlim(left=0)
        ax_fwd.set_ylim(bottom=0)
    else:
        ax_fwd.text(0.5, 0.5, "No Forward Data", ha="center", va="center")

    # Reverse
    if reverse_throughput:
        for label, t, th in reverse_throughput:
            ax_rev.plot(t, th, marker="x", markersize=6, alpha=0.9, label=label)
        ax_rev.set_title("Reverse")
        ax_rev.set_xlabel("Time (s)")
        ax_rev.grid(True)
        ax_rev.legend()
        # Force x=0 and y=0 to appear
        ax_rev.set_xlim(left=0)
        ax_rev.set_ylim(bottom=0)
    else:
        ax_rev.text(0.5, 0.5, "No Reverse Data", ha="center", va="center")

    # After plotting the data on both subplots, compute the overall maximum throughput
    all_throughput_values = []
    for _, _, th in forward_throughput + reverse_throughput:
        all_throughput_values.extend(th)

    if all_throughput_values:
        # Compute maximum and add a 10% margin
        max_val = max(all_throughput_values)
        y_max = max_val * 1.1

        # Set the same y-axis limits on both subplots
        ax_fwd.set_ylim(0, y_max)
        ax_rev.set_ylim(0, y_max)

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    throughput_file = os.path.join(args.out_dir, "comparison_throughput.png")
    fig.savefig(throughput_file)
    plt.close(fig)
    print(f"Saved throughput comparison plot to {throughput_file}")

    # ----- RTT Comparison Plot (Linear Scale) -----
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.suptitle("iperf3 RTT Comparison (ms)", fontsize=16)

    if all_rtt:
        for label, t, r in all_rtt:
            # Skip plotting if all RTT values are None
            if all(rr is None for rr in r):
                continue

            # Use 'x' marker for Reverse tests to distinguish
            marker_style = "x" if "Reverse" in label else "o"

            ax.plot(
                t,
                r,
                marker=marker_style,
                alpha=0.8,
                label=label,
            )

        ax.set_xlabel("Time (s)")
        ax.set_ylabel("RTT (ms)")
        ax.grid(True)
        ax.legend()
        # Ensure axes start at zero (if applicable)
        ax.set_xlim(left=0)
        ax.set_ylim(bottom=0)
    else:
        ax.text(0.5, 0.5, "No RTT Data", ha="center", va="center")

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    rtt_linear_file = os.path.join(args.out_dir, "comparison_rtt.png")
    fig.savefig(rtt_linear_file)
    plt.close(fig)
    print(f"Saved RTT comparison plot (linear scale) to {rtt_linear_file}")

    # ----- RTT Comparison Plot (Logarithmic Scale) -----
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.suptitle("iperf3 RTT Comparison (ms)", fontsize=16)

    if all_rtt:
        for label, t, r in all_rtt:
            # Skip plotting if all RTT values are None
            if all(rr is None for rr in r):
                continue

            # Use 'x' marker for Reverse tests to distinguish
            marker_style = "x" if "Reverse" in label else "o"

            ax.plot(
                t,
                r,
                marker=marker_style,
                alpha=0.8,
                label=label,
            )

        ax.set_xlabel("Time (s)")
        ax.set_ylabel("RTT (ms)")
        ax.grid(True)
        ax.legend()
        ax.set_xlim(left=0)
        # Use a logarithmic scale for the y-axis.
        ax.set_yscale("log")
    else:
        ax.text(0.5, 0.5, "No RTT Data", ha="center", va="center")

    plt.tight_layout(rect=[0, 0, 1, 0.95])
    rtt_log_file = os.path.join(args.out_dir, "comparison_rtt_log.png")
    fig.savefig(rtt_log_file)
    plt.close(fig)
    print(f"Saved RTT comparison plot (log scale) to {rtt_log_file}")


if __name__ == "__main__":
    main()
