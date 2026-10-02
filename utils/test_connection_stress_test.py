#!/usr/bin/env python3
"""
Unit tests for the CST benchmark tool.
"""

import asyncio
import io
import logging
import time
import unittest
from click.testing import CliRunner

# Import the benchmark module.
import connection_stress_test as benchmark


class TestBenchmark(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        # Ignore ResourceWarning from unclosed sockets.
        import warnings

        warnings.simplefilter("ignore", ResourceWarning)

        # Reset the global state in the benchmark module.
        benchmark.global_total_up_bytes = 0
        benchmark.global_total_down_bytes = 0
        benchmark.connection_counter = 0
        benchmark.active_up_stats.clear()
        benchmark.active_down_stats.clear()
        benchmark.connection_transfer_times.clear()
        benchmark.connection_transfer_rates.clear()
        benchmark.connection_setup_times.clear()
        benchmark.connection_teardown_times.clear()
        benchmark.error_occurred = False

    def test_get_new_connection_id(self):
        id1 = benchmark.get_new_connection_id("T")
        id2 = benchmark.get_new_connection_id("T")
        self.assertNotEqual(id1, id2)
        self.assertTrue(id1.startswith("T"))
        self.assertTrue(id2.startswith("T"))

    def test_format_mb(self):
        # 1 MB should be formatted as "1.00"
        self.assertEqual(benchmark.format_mb(1024 * 1024), "1.00")
        # Check for a different value
        expected = f"{(512 * 1024) / (1024 * 1024):.2f}"
        self.assertEqual(benchmark.format_mb(512 * 1024), expected)

    def test_summarize_list(self):
        data = [1, 2, 3, 4]
        avg, min_val, max_val, var = benchmark.summarize_list(data)
        self.assertAlmostEqual(avg, 2.5)
        self.assertEqual(min_val, 1)
        self.assertEqual(max_val, 4)
        # For [1,2,3,4], variance = 1.66667 (sample variance)
        self.assertAlmostEqual(var, 1.66667, places=4)

    async def test_send_receive_blocks(self):
        total_bytes = 1024
        block_size = 256

        # Define a simple server handler that calls receive_blocks.
        async def handle_client(reader, writer):
            try:
                await benchmark.receive_blocks(
                    reader, total_bytes, block_size, "SERVER"
                )
            except Exception as e:
                writer.close()
                raise
            # Close writer (ignoring write_eof if unsupported)
            await benchmark.close_writer(writer)

        # Start a server on an ephemeral port.
        server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
        addr = server.sockets[0].getsockname()

        # Client: run send_blocks.
        reader, writer = await asyncio.open_connection(*addr)
        await benchmark.send_blocks(writer, total_bytes, block_size, "CLIENT")
        await benchmark.close_writer(writer)

        # Give the server a moment to finish.
        await asyncio.sleep(0.1)
        server.close()
        await server.wait_closed()

        # Check that the globals were updated correctly.
        self.assertEqual(benchmark.global_total_up_bytes, total_bytes)
        self.assertEqual(benchmark.global_total_down_bytes, total_bytes)

    async def test_exercise_connection(self):
        total_bytes = 1024
        block_size = 256

        async def server_handler(reader, writer):
            try:
                await benchmark.exercise_connection(
                    reader, writer, total_bytes, block_size, "SERVER"
                )
            finally:
                await benchmark.close_writer(writer)

        server = await asyncio.start_server(server_handler, "127.0.0.1", 0)
        addr = server.sockets[0].getsockname()

        client_reader, client_writer = await asyncio.open_connection(*addr)
        client_task = asyncio.create_task(
            benchmark.exercise_connection(
                client_reader, client_writer, total_bytes, block_size, "CLIENT"
            )
        )

        await client_task
        server.close()
        await server.wait_closed()

        self.assertEqual(benchmark.global_total_up_bytes, 2 * total_bytes)
        self.assertEqual(benchmark.global_total_down_bytes, 2 * total_bytes)

    async def test_monitor_stats(self):
        # Set globals to simulate that expected totals have been reached.
        benchmark.global_total_up_bytes = 1024
        benchmark.global_total_down_bytes = 2048
        expected_up = 1024
        expected_down = 2048

        # The monitor_stats loop should exit immediately if totals are met.
        start = time.time()
        await benchmark.monitor_stats(expected_up, expected_down, update_interval=0.1)
        elapsed = time.time() - start
        self.assertLess(elapsed, 1.0)  # should complete in under 1 second

    def test_print_benchmark_summary(self):
        # Set up a log stream to capture logging output.
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)  # Ensure INFO-level messages are captured.
        logger.addHandler(handler)

        # Set global benchmark values.
        benchmark.global_total_up_bytes = 1024 * 1024  # 1 MB
        benchmark.global_total_down_bytes = 2 * 1024 * 1024  # 2 MB
        benchmark.connection_transfer_times[:] = [1.0, 2.0, 1.5]
        benchmark.connection_transfer_rates[:] = [1.0, 0.5, 0.75]
        benchmark.connection_setup_times[:] = [0.1, 0.2]
        benchmark.connection_teardown_times[:] = [0.05, 0.07]
        benchmark.connection_counter = 42  # Simulate 42 listener connections accepted.

        # Set parameters for the benchmark.
        workers = 10
        block_size = 1024  # bytes
        total_bytes = 2048  # bytes per direction per connection

        # Call the updated summary function with all required parameters.
        benchmark.print_benchmark_summary(5.0, workers, block_size, total_bytes)

        handler.flush()
        output = log_stream.getvalue()
        self.assertIn("Overall benchmark duration:", output)
        self.assertIn("Benchmark parameters:", output)
        self.assertIn(" - Worker connections:", output)
        self.assertIn(" - Listener connections accepted:", output)
        self.assertIn(" - Block size:", output)
        self.assertIn(" - Total bytes per direction per connection:", output)
        self.assertIn("Total UP:", output)
        self.assertIn("Total DOWN:", output)
        self.assertIn("Connection transfer time", output)
        self.assertIn("Connection setup time", output)
        self.assertIn("Connection teardown time", output)

        # Clean up: remove our log handler.
        logger.removeHandler(handler)

    def test_colored_formatter(self):
        # Test that the ColoredFormatter adds ANSI color codes.
        formatter = benchmark.ColoredFormatter("%(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.funcName = "send_blocks"  # This should map to a specific color.
        formatted = formatter.format(record)
        # Check that the formatted string contains ANSI escape sequences.
        self.assertIn("\033[", formatted)

    def test_cli(self):
        runner = CliRunner()

        async def dummy_async_main(*args, **kwargs):
            import click

            click.echo("Benchmark complete.")
            return

        original_async_main = benchmark.async_main
        benchmark.async_main = dummy_async_main

        result = runner.invoke(
            benchmark.cli,
            [
                "--workers",
                "1",
                "--block-size",
                "256",
                "--total-bytes",
                "1024",
                "--server-host",
                "127.0.0.1",
                "--server-port",
                "10003",
                "--listener-host",
                "127.0.0.1",
                "--listener-port",
                "5201",
            ],
        )
        benchmark.async_main = original_async_main

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Benchmark", result.output)


if __name__ == "__main__":
    unittest.main()
