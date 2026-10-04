#!/usr/bin/env python3
"""Measures the throughput of a PortRedirect tunnel over an emulated network link.

For each case, it starts an iperf3 server as the destination, portredirect_server,
the link emulator (utils/link_emulator.rs) between client and server, and
portredirect_client, then runs an iperf3 client through the tunnel and prints a
Markdown table of the results. See docs/PERFORMANCE.md.

Build the programs first:

    cargo build --release --bins --example link_emulator

Example: round-trip times of 0, 50 and 150 ms, without and with 1 % loss, one and
ten connections, 12 seconds each:

    utils/link_benchmark.py --rtt 0 50 150 --loss 0 1 --parallel 1 10
"""

import argparse
import itertools
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

PSK = "link-benchmark-psk-0123456789"
DESTINATION_PORT = 15201
LISTEN_PORT = 15001
QUIC_PORT = 15433
EMULATOR_PORT = 15434


def start(command, log, env=None):
    """Starts a program in the background, with its output in the file `log`."""
    output = open(log, "w")
    return subprocess.Popen(
        command,
        stdout=output,
        stderr=subprocess.STDOUT,
        env={**os.environ, **(env or {})},
    )


def wait_for_text(path, text, timeout):
    """Waits until the file `path` contains `text`; returns whether it did in time."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with open(path) as log:
            if text in log.read():
                return True
        time.sleep(0.1)
    return False


def stop(process, sig=signal.SIGTERM):
    """Stops a program and waits for it to end."""
    if process.poll() is None:
        process.send_signal(sig)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def measure(args, case, log_dir):
    """Runs one case; returns the throughput in Mbit/s, or None if the run failed."""
    rtt, loss, parallel, reverse = case
    bin_dir = args.bin_dir
    config_dir = tempfile.mkdtemp(dir=log_dir)
    quic_port = EMULATOR_PORT if rtt or loss or args.rate else QUIC_PORT
    processes = []
    try:
        processes.append(
            start(
                ["iperf3", "-s", "-p", str(DESTINATION_PORT)],
                f"{log_dir}/iperf3_server.log",
            )
        )
        server = start(
            [
                f"{bin_dir}/portredirect_server",
                "--config-dir",
                config_dir,
                "--listen-host",
                "127.0.0.1",
                "--allowed-client-ports",
                str(LISTEN_PORT),
                "--quic-listen-host",
                "127.0.0.1",
                "--quic-listen-port",
                str(QUIC_PORT),
                "--psk",
                PSK,
                "--congestion-control",
                args.congestion_control,
                "--log-level",
                "warn",
            ],
            f"{log_dir}/server.log",
            args.env,
        )
        processes.append(server)
        if quic_port == EMULATOR_PORT:
            emulator = start(
                [
                    f"{bin_dir}/examples/link_emulator",
                    "--listen",
                    f"127.0.0.1:{EMULATOR_PORT}",
                    "--upstream",
                    f"127.0.0.1:{QUIC_PORT}",
                    "--rtt-ms",
                    str(rtt),
                    "--loss-percent",
                    str(loss),
                    "--rate-mbit",
                    str(args.rate),
                ],
                f"{log_dir}/emulator.log",
            )
            processes.append(emulator)
        # The client needs the server's certificate, which the server generates.
        deadline = time.monotonic() + 10
        while not os.path.exists(f"{config_dir}/cert.der"):
            if time.monotonic() > deadline:
                return None
            time.sleep(0.1)
        client = start(
            [
                f"{bin_dir}/portredirect_client",
                "--config-dir",
                config_dir,
                "--destination-host",
                "127.0.0.1",
                "--destination-port",
                str(DESTINATION_PORT),
                "--remote-listen-port",
                str(LISTEN_PORT),
                "--quic-remote-host",
                "127.0.0.1",
                "--quic-remote-port",
                str(quic_port),
                "--psk",
                PSK,
                "--congestion-control",
                args.congestion_control,
                "--log-level",
                "info",
            ],
            f"{log_dir}/client.log",
            args.env,
        )
        processes.append(client)
        if not wait_for_text(f"{log_dir}/client.log", "Tunnel established", 20):
            return None
        command = [
            "iperf3",
            "-c",
            "127.0.0.1",
            "-p",
            str(LISTEN_PORT),
            "-t",
            str(args.duration),
            "-O",
            str(args.omit),
            "-P",
            str(parallel),
            "-J",
        ]
        if reverse:
            command.append("-R")
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=args.duration + 60
        )
        with open(f"{log_dir}/iperf3_client.json", "w") as log:
            log.write(result.stdout)
        report = json.loads(result.stdout)
        if "error" in report:
            return None
        return report["end"]["sum_received"]["bits_per_second"] / 1e6
    except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError):
        return None
    finally:
        # The emulator prints its counts on SIGINT.
        for process in reversed(processes):
            stop(process, signal.SIGINT)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--bin-dir", default="target/release")
    parser.add_argument("--rtt", type=int, nargs="+", default=[0, 50, 150])
    parser.add_argument("--loss", type=float, nargs="+", default=[0, 1])
    parser.add_argument("--parallel", type=int, nargs="+", default=[1, 10])
    parser.add_argument(
        "--reverse",
        action="store_true",
        help="data from the destination to the external client",
    )
    parser.add_argument("--rate", type=int, default=0, help="bandwidth in Mbit/s")
    parser.add_argument(
        "--congestion-control",
        default="cubic",
        help="--congestion-control of server and client",
    )
    parser.add_argument("--duration", type=int, default=12)
    parser.add_argument(
        "--omit", type=int, default=2, help="seconds left out at the start"
    )
    parser.add_argument(
        "--env",
        nargs="*",
        default=[],
        help="environment variables for server and client, NAME=VALUE",
    )
    parser.add_argument("--label", default="", help="text for the first column")
    parser.add_argument("--log-dir", default=None)
    args = parser.parse_args()
    args.env = dict(item.split("=", 1) for item in args.env)

    log_root = args.log_dir or tempfile.mkdtemp(prefix="link_benchmark_")
    print(f"| {'label':<20} | RTT ms | loss % | streams | Mbit/s |", flush=True)
    print(f"|{'-' * 22}|-------:|-------:|--------:|-------:|", flush=True)
    for number, case in enumerate(
        itertools.product(args.rtt, args.loss, args.parallel, [args.reverse])
    ):
        log_dir = f"{log_root}/{number}"
        os.makedirs(log_dir, exist_ok=True)
        mbit = measure(args, case, log_dir)
        rtt, loss, parallel, _ = case
        result = f"{mbit:7.1f}" if mbit is not None else "failed"
        print(
            f"| {args.label:<20} | {rtt:6} | {loss:6} | {parallel:7} | {result:>6} |",
            flush=True,
        )
    print(f"Logs: {log_root}", file=sys.stderr)


if __name__ == "__main__":
    main()
