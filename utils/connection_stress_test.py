#!/usr/bin/env python3
"""
Benchmark script for testing performance and data integrity through a tunnel.
It spawns a TCP listener (which portredirect's client side will connect to)
and concurrently launches several workers that connect to a separate TCP port
(portredirect's server side). Once a connection is established (via PR tunnel),
both sides run a bidirectional data transfer test that sends pseudorandom blocks
with a CRC32 checksum appended.

The block protocol is defined as follows:
    - For each block, a header (8 bytes) is sent:
         • 4 bytes: current block length (unsigned int, network byte order)
         • 4 bytes: CRC32 checksum computed on the block data
    - Then the block data (of the indicated length) is sent.
The receiver reads the header, then the data block, computes the checksum on the fly,
and compares it with the transmitted value. This avoids having to store a copy of
the expected data for later verification.
"""

import asyncio
import os
import struct
import zlib
import time
import logging
import sys
import click
import statistics
from functools import partial

# -----------------------------
# Global statistics and error flag
# -----------------------------
global_total_up_bytes = 0
global_total_down_bytes = 0
active_up_stats = {}
active_down_stats = {}
connection_counter = 0
error_occurred = False  # set to True if any data error or exception occurs

# Global profiling lists
connection_setup_times = []  # how long it took to set up a connection
connection_teardown_times = []  # how long it took to tear down a connection
connection_transfer_times = []  # overall transfer time per connection
connection_transfer_rates = []  # MB/s per connection (each direction)


def get_new_connection_id(prefix: str = "L") -> str:
    """Generate a unique connection ID with a given prefix (e.g. 'L' for listener)."""
    global connection_counter
    connection_counter += 1
    return f"{prefix}{connection_counter}"


# -----------------------------
# Improved Colored logging formatter
# -----------------------------
class ColoredFormatter(logging.Formatter):
    # ANSI escape codes for colors.
    GRAY = "\033[90m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[0m"

    # Map function names to distinctive colors.
    FUNCTION_COLORS = {
        "send_blocks": BLUE,
        "receive_blocks": MAGENTA,
        "exercise_connection": CYAN,
        "worker": GREEN,
        "run_workers": GREEN,
        "handle_connection": YELLOW,
        "tcp_listener": WHITE,
        # monitor_stats is handled separately (it builds its own colored message)
    }

    def formatTime(self, record, datefmt=None):
        # Format the time and wrap it in gray.
        t = super().formatTime(record, datefmt)
        return f"{self.GRAY}{t}{self.RESET}"

    def format(self, record):
        # First, ensure the timestamp is colored gray.
        record.asctime = self.formatTime(record)
        # Determine the color to use.
        # For errors, always force red.
        if record.levelno >= logging.ERROR:
            func_color = self.RED
        # For monitor_stats, we assume the message is already pre-colored.
        elif record.funcName == "monitor_stats":
            func_color = ""
        else:
            func_color = self.FUNCTION_COLORS.get(record.funcName, self.CYAN)
        # Wrap the message in the chosen function color.
        record.msg = f"{func_color}{record.msg}{self.RESET}"
        return super().format(record)


def setup_logging(log_file=None):
    # Create a stream (console) handler with colored output.
    handler = logging.StreamHandler()
    formatter = ColoredFormatter("%(asctime)s %(levelname)s: %(message)s")
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # Remove any other handlers
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(handler)

    # If a log file is provided, add a file handler.
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)


# -----------------------------
# Utility for formatting bytes as MB
# -----------------------------
def format_mb(value: float) -> str:
    """Convert a value in bytes to a string representing megabytes (MB) with two decimals."""
    return f"{value / (1024 * 1024):.2f}"


# -----------------------------
# Utility for closing a writer cleanly
# -----------------------------
async def close_writer(writer: asyncio.StreamWriter) -> None:
    """Close the writer and wait for it to close."""
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


# -----------------------------
# Data transfer functions
# -----------------------------
async def send_blocks(
    writer: asyncio.StreamWriter,
    total_bytes: int,
    block_size: int,
    conn_id: str,
) -> None:
    """
    Generate and send pseudorandom data blocks (with CRC32 checksum header)
    until a total number of bytes have been transmitted.
    Also update global stats for the up direction.
    """
    global global_total_up_bytes, active_up_stats, error_occurred
    bytes_sent = 0
    active_up_stats[conn_id] = {
        "last_time": time.time(),
        "last_bytes": 0,
        "current_speed": 0,
    }

    while bytes_sent < total_bytes:
        current_block_size = min(block_size, total_bytes - bytes_sent)
        try:
            data = os.urandom(current_block_size)
        except Exception as e:
            logging.exception("Error generating random data on conn %s", conn_id)
            error_occurred = True
            raise

        checksum = zlib.crc32(data) & 0xFFFFFFFF
        header = struct.pack("!II", current_block_size, checksum)
        writer.write(header + data)
        await writer.drain()

        bytes_sent += current_block_size
        global_total_up_bytes += current_block_size
        now = time.time()
        stats = active_up_stats[conn_id]
        delta = bytes_sent - stats["last_bytes"]
        dt = now - stats["last_time"]
        speed = delta / dt if dt > 0 else 0
        stats["current_speed"] = speed
        stats["last_bytes"] = bytes_sent
        stats["last_time"] = now

    try:
        writer.write_eof()
    except Exception:
        pass  # Some transports do not support write_eof()


async def receive_blocks(
    reader: asyncio.StreamReader, total_bytes: int, block_size: int, conn_id: str
) -> None:
    """
    Receive data blocks (with header) until a total number of bytes have been read.
    For each block, compute the CRC32 checksum on the fly and compare it to the transmitted value.
    Also update global stats for the down direction.
    """
    global global_total_down_bytes, active_down_stats, error_occurred
    bytes_received = 0
    active_down_stats[conn_id] = {
        "last_time": time.time(),
        "last_bytes": 0,
        "current_speed": 0,
    }

    while bytes_received < total_bytes:
        header = await reader.readexactly(8)
        current_block_size, expected_checksum = struct.unpack("!II", header)
        data = await reader.readexactly(current_block_size)
        computed_checksum = zlib.crc32(data) & 0xFFFFFFFF
        if computed_checksum != expected_checksum:
            logging.error(
                "Checksum mismatch on conn %s: expected %08x, got %08x",
                conn_id,
                expected_checksum,
                computed_checksum,
            )
            error_occurred = True
            raise ValueError(f"Checksum mismatch on connection {conn_id}")
        bytes_received += current_block_size
        global_total_down_bytes += current_block_size
        now = time.time()
        stats = active_down_stats[conn_id]
        delta = bytes_received - stats["last_bytes"]
        dt = now - stats["last_time"]
        speed = delta / dt if dt > 0 else 0
        stats["current_speed"] = speed
        stats["last_bytes"] = bytes_received
        stats["last_time"] = now


async def exercise_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    total_bytes: int,
    block_size: int,
    conn_id: str,
) -> None:
    """
    Run bidirectional transmission on a connection.
    Launch send and receive tasks concurrently and log the overall speed.
    Also record the overall transfer time and per‑connection speed.
    """
    global error_occurred, connection_transfer_times, connection_transfer_rates
    peer = writer.get_extra_info("peername")
    logging.info("Starting transfer on connection %s (peer: %s)", conn_id, peer)
    start_time = time.time()
    send_task = asyncio.create_task(
        send_blocks(writer, total_bytes, block_size, conn_id)
    )
    recv_task = asyncio.create_task(
        receive_blocks(reader, total_bytes, block_size, conn_id)
    )
    try:
        await asyncio.gather(send_task, recv_task)
    except Exception as e:
        logging.exception("Error in connection %s: %s", conn_id, e)
        error_occurred = True
        raise

    elapsed = time.time() - start_time
    mb = total_bytes / (1024 * 1024)
    rate = mb / elapsed if elapsed > 0 else 0
    logging.info(
        "Connection %s complete in %.2f s (%.2f MB/s each direction)",
        conn_id,
        elapsed,
        rate,
    )
    connection_transfer_times.append(elapsed)
    connection_transfer_rates.append(rate)
    active_up_stats.pop(conn_id, None)
    active_down_stats.pop(conn_id, None)


# -----------------------------
# Worker (client) side
# -----------------------------
async def worker(
    worker_id: int, server_addr: tuple, total_bytes: int, block_size: int
) -> None:
    """
    A worker that connects to the tunnel’s server side and runs the transmission test.
    Uses the worker's unique ID as part of its connection ID.
    Also profiles the connection setup and teardown durations.
    """
    global error_occurred, connection_setup_times, connection_teardown_times
    conn_id = f"W{worker_id}"
    logging.info(
        "Worker %s: connecting to %s:%d", conn_id, server_addr[0], server_addr[1]
    )
    setup_start = time.time()
    try:
        reader, writer = await asyncio.open_connection(*server_addr)
    except Exception as e:
        logging.exception("Worker %s: failed to connect: %s", conn_id, e)
        error_occurred = True
        raise
    setup_duration = time.time() - setup_start
    connection_setup_times.append(setup_duration)
    logging.info("Worker %s: connection setup took %.4f s", conn_id, setup_duration)

    try:
        await exercise_connection(reader, writer, total_bytes, block_size, conn_id)
    except Exception as e:
        logging.exception("Worker %s encountered an error: %s", conn_id, e)
        raise
    finally:
        teardown_start = time.time()
        await close_writer(writer)
        teardown_duration = time.time() - teardown_start
        connection_teardown_times.append(teardown_duration)
        logging.info(
            "Worker %s: connection closed (teardown took %.4f s)",
            conn_id,
            teardown_duration,
        )


async def run_workers(
    num_workers: int, server_addr: tuple, total_bytes: int, block_size: int
) -> None:
    """Launch worker coroutines with a slight stagger between startups."""
    tasks = []
    for i in range(num_workers):
        tasks.append(
            asyncio.create_task(worker(i, server_addr, total_bytes, block_size))
        )
        await asyncio.sleep(0.01)
    results = await asyncio.gather(*tasks, return_exceptions=True)
    # Propagate any exceptions that occurred in any worker.
    for result in results:
        if isinstance(result, Exception):
            raise result


# -----------------------------
# TCP Listener (server) side
# -----------------------------
async def handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    total_bytes: int,
    block_size: int,
) -> None:
    """
    Handle an incoming connection on our TCP listener.
    Generate a unique connection ID.
    """
    conn_id = get_new_connection_id("L")
    peer = writer.get_extra_info("peername")
    logging.info("Accepted connection %s from %s", conn_id, peer)
    try:
        await exercise_connection(reader, writer, total_bytes, block_size, conn_id)
    except Exception as e:
        logging.exception("Error handling connection %s from %s: %s", conn_id, peer, e)
        global error_occurred
        error_occurred = True
        raise
    finally:
        await close_writer(writer)
        logging.info("Closed connection %s from %s", conn_id, peer)


async def tcp_listener(host: str, port: int, total_bytes: int, block_size: int) -> None:
    """
    Create a TCP listener on (host, port) and serve forever.
    Each new connection is handled by handle_connection().
    """
    server = await asyncio.start_server(
        partial(handle_connection, total_bytes=total_bytes, block_size=block_size),
        host,
        port,
    )
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    logging.info("TCP listener running on %s", addrs)
    async with server:
        await server.serve_forever()


# -----------------------------
# Monitor for realtime stats
# -----------------------------
async def monitor_stats(
    expected_up: int, expected_down: int, update_interval: float = 1.0
) -> None:
    """
    Periodically (every update_interval seconds) compute and log realtime stats:
      - For each direction: min/max/avg instantaneous speeds (MB/s) among active connections.
      - Total bytes transmitted and percent progress.
    Stops monitoring once both UP and DOWN transfers have reached their expected totals.
    """
    YELLOW = ColoredFormatter.YELLOW
    RED = ColoredFormatter.RED
    GREEN = ColoredFormatter.GREEN
    RESET = ColoredFormatter.RESET
    while True:
        await asyncio.sleep(update_interval)
        speeds_up = [stats["current_speed"] for stats in active_up_stats.values()]
        if speeds_up:
            min_speed_up = min(speeds_up)
            max_speed_up = max(speeds_up)
            avg_speed_up = sum(speeds_up) / len(speeds_up)
        else:
            min_speed_up = max_speed_up = avg_speed_up = 0

        speeds_down = [stats["current_speed"] for stats in active_down_stats.values()]
        if speeds_down:
            min_speed_down = min(speeds_down)
            max_speed_down = max(speeds_down)
            avg_speed_down = sum(speeds_down) / len(speeds_down)
        else:
            min_speed_down = max_speed_down = avg_speed_down = 0

        progress_up = (global_total_up_bytes / expected_up * 100) if expected_up else 0
        progress_down = (
            (global_total_down_bytes / expected_down * 100) if expected_down else 0
        )

        msg = (
            f"{RED}UP:{RESET} {format_mb(global_total_up_bytes)} MB transferred "
            f"({progress_up:.2f}% complete) | Speed: min: {GREEN}{format_mb(min_speed_up)}{RESET} MB/s, "
            f"max: {GREEN}{format_mb(max_speed_up)}{RESET} MB/s, avg: {YELLOW}{format_mb(avg_speed_up)}{RESET} MB/s || "
            f"{RED}DOWN:{RESET} {format_mb(global_total_down_bytes)} MB transferred "
            f"({progress_down:.2f}% complete) | Speed: min: {GREEN}{format_mb(min_speed_down)}{RESET} MB/s, "
            f"max: {GREEN}{format_mb(max_speed_down)}{RESET} MB/s, avg: {YELLOW}{format_mb(avg_speed_down)}{RESET} MB/s{RESET}"
        )
        logging.info(msg)

        # Stop monitoring if both directions have reached (or exceeded) their expected totals.
        if (
            global_total_up_bytes >= expected_up
            and global_total_down_bytes >= expected_down
        ):
            break


# -----------------------------
# Benchmark Header Function (Printed at the beginning of the test)
# -----------------------------


def print_benchmark_header(
    workers: int,
    block_size: int,
    total_bytes: int,
    server_host: str,
    server_port: int,
    listener_host: str,
    listener_port: int,
):
    """Print a header with benchmark parameters and the full command line used."""
    logging.info("========== Benchmark Header ==========")
    logging.info("Command line: %s", " ".join(sys.argv))
    logging.info("Benchmark parameters:")
    logging.info(" - Worker connections: %d", workers)
    logging.info(" - Block size: %d bytes", block_size)
    logging.info(" - Total bytes per connection: %d", total_bytes)
    logging.info(" - Server host: %s", server_host)
    logging.info(" - Server port: %d", server_port)
    logging.info(" - Listener host: %s", listener_host)
    logging.info(" - Listener port: %d", listener_port)
    logging.info("======================================")


# -----------------------------
# Benchmark Summary Function (Printed after the test)
# -----------------------------
def summarize_list(times_list):
    """Return average, min, max, and variance of a list of floats."""
    if not times_list:
        return 0, 0, 0, 0
    avg = statistics.mean(times_list)
    min_val = min(times_list)
    max_val = max(times_list)
    var = statistics.variance(times_list) if len(times_list) > 1 else 0.0
    return avg, min_val, max_val, var


def print_benchmark_summary(
    overall_elapsed: float, workers: int, block_size: int, total_bytes: int
):
    """Print a detailed summary of the benchmark performance and profiling data."""
    total_up_str = format_mb(global_total_up_bytes)
    total_down_str = format_mb(global_total_down_bytes)
    total_up_mb = global_total_up_bytes / (1024 * 1024)
    total_down_mb = global_total_down_bytes / (1024 * 1024)
    overall_up_rate = total_up_mb / overall_elapsed if overall_elapsed > 0 else 0
    overall_down_rate = total_down_mb / overall_elapsed if overall_elapsed > 0 else 0

    logging.info("========== Benchmark Summary ==========")
    logging.info("Overall benchmark duration: %.2f s", overall_elapsed)
    logging.info("Benchmark parameters:")
    logging.info(" - Worker connections: %d", workers)
    logging.info(" - Listener connections accepted: %d", connection_counter)
    logging.info(" - Block size: %d bytes", block_size)
    logging.info(" - Total bytes per direction per connection: %d bytes", total_bytes)
    logging.info(
        "Total UP:   %s MB  (avg speed: %.2f MB/s)", total_up_str, overall_up_rate
    )
    logging.info(
        "Total DOWN: %s MB  (avg speed: %.2f MB/s)", total_down_str, overall_down_rate
    )

    if connection_transfer_times:
        avg_time, min_time, max_time, var_time = summarize_list(
            connection_transfer_times
        )
        logging.info(
            "Connection transfer time (s): avg: %.2f, min: %.2f, max: %.2f, variance: %.4f",
            avg_time,
            min_time,
            max_time,
            var_time,
        )
    if connection_transfer_rates:
        avg_rate, min_rate, max_rate, var_rate = summarize_list(
            connection_transfer_rates
        )
        logging.info(
            "Connection transfer rate (MB/s): avg: %.2f, min: %.2f, max: %.2f, variance: %.4f",
            avg_rate,
            min_rate,
            max_rate,
            var_rate,
        )

        # Identify the fastest and slowest connection samples (by transfer rate)
        fastest_rate = max(connection_transfer_rates)
        slowest_rate = min(connection_transfer_rates)
        fastest_index = connection_transfer_rates.index(fastest_rate)
        slowest_index = connection_transfer_rates.index(slowest_rate)
        fastest_time = connection_transfer_times[fastest_index]
        slowest_time = connection_transfer_times[slowest_index]
        logging.info(
            "Fastest connection sample: transfer time = %.2f s, rate = %.2f MB/s",
            fastest_time,
            fastest_rate,
        )
        logging.info(
            "Slowest connection sample: transfer time = %.2f s, rate = %.2f MB/s",
            slowest_time,
            slowest_rate,
        )

    if connection_setup_times:
        avg_setup, min_setup, max_setup, var_setup = summarize_list(
            connection_setup_times
        )
        logging.info(
            "Connection setup time (s): avg: %.4f, min: %.4f, max: %.4f, variance: %.6f",
            avg_setup,
            min_setup,
            max_setup,
            var_setup,
        )
    if connection_teardown_times:
        avg_teardown, min_teardown, max_teardown, var_teardown = summarize_list(
            connection_teardown_times
        )
        logging.info(
            "Connection teardown time (s): avg: %.4f, min: %.4f, max: %.4f, variance: %.6f",
            avg_teardown,
            min_teardown,
            max_teardown,
            var_teardown,
        )
    logging.info("=======================================")


# -----------------------------
# Main function and CLI via Click
# -----------------------------
async def async_main(
    workers: int,
    block_size: int,
    total_bytes: int,
    server_host: str,
    server_port: int,
    listener_host: str,
    listener_port: int,
    log_file: str = None,
) -> None:
    setup_logging(log_file)

    # Print the header with full CLI details at the start.
    print_benchmark_header(
        workers,
        block_size,
        total_bytes,
        server_host,
        server_port,
        listener_host,
        listener_port,
    )

    # Expected total bytes per direction across all endpoints.
    # Each tunnel connection has two endpoints, so the global totals will be 2 * workers * total_bytes.
    expected_total_up = 2 * workers * total_bytes
    expected_total_down = 2 * workers * total_bytes

    listener_task = asyncio.create_task(
        tcp_listener(listener_host, listener_port, total_bytes, block_size)
    )
    # Give the listener a moment to start.
    await asyncio.sleep(1)

    monitor_task = asyncio.create_task(
        monitor_stats(expected_total_up, expected_total_down, update_interval=1)
    )

    # Record overall benchmark start time (workers side)
    benchmark_start_time = time.time()
    try:
        await run_workers(workers, (server_host, server_port), total_bytes, block_size)
    except Exception as e:
        logging.error("× Worker connections failed: %s", e)
        # Cancel tasks before propagating the error.
        listener_task.cancel()
        monitor_task.cancel()
        raise
    benchmark_end_time = time.time()
    overall_elapsed = benchmark_end_time - benchmark_start_time

    # Wait a moment for monitor_stats to finish if it hasn't already.
    try:
        await monitor_task
    except asyncio.CancelledError:
        logging.info("✓ Monitor task cancelled.")

    listener_task.cancel()
    try:
        await listener_task
    except asyncio.CancelledError:
        logging.info("✓ TCP listener cancelled.")

    print_benchmark_summary(overall_elapsed, workers, block_size, total_bytes)

    if error_occurred:
        logging.error("××× Benchmark completed with errors.")
        # Raising an exception here ensures that the process will exit with status 1.
        raise RuntimeError("××× Benchmark encountered errors.")
    else:
        logging.info("✓✓✓ Benchmark complete.")


@click.command()
@click.option(
    "--workers",
    default=100,
    show_default=True,
    type=int,
    help="Number of worker connections to launch.",
)
@click.option(
    "--block-size",
    default=1024 * 64,
    show_default=True,
    type=int,
    help="Block size in bytes used when sending data.",
)
@click.option(
    "--total-bytes",
    default=1024 * 1024 * 4,
    show_default=True,
    type=int,
    help="Total bytes to send per direction per connection.",
)
@click.option(
    "--server-host",
    default="127.0.0.1",
    show_default=True,
    type=str,
    help="Tunnel's server side host (for worker connections).",
)
@click.option(
    "--server-port",
    default=10003,
    show_default=True,
    type=int,
    help="Tunnel's server side port.",
)
@click.option(
    "--listener-host",
    default="127.0.0.1",
    show_default=True,
    type=str,
    help="Host for the TCP listener (tunnel's client side).",
)
@click.option(
    "--listener-port",
    default=5201,
    show_default=True,
    type=int,
    help="Port for the TCP listener.",
)
@click.option(
    "--log-file", default=None, type=str, help="File to write additional log output."
)
def cli(
    workers,
    block_size,
    total_bytes,
    server_host,
    server_port,
    listener_host,
    listener_port,
    log_file,
):
    """
    Benchmark tool for testing tunnel performance and data integrity.
    Exits with code 1 if any error or data integrity issue is detected.
    """
    try:
        asyncio.run(
            async_main(
                workers,
                block_size,
                total_bytes,
                server_host,
                server_port,
                listener_host,
                listener_port,
                log_file,
            )
        )
    except Exception as e:
        logging.error("Benchmark failed: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    cli()
