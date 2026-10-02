import os
import tempfile
import unittest
import pandas as pd
from cst_datacruncher import (
    parse_transfer_metrics,
    load_logs,
)

# Sample log messages for testing
MESSAGE1 = (
    "2025-02-14 07:17:58,776 INFO: UP: 447.69 MB transferred (22.38% complete) | Speed: min: 74.58 MB/s, max: 177.97 MB/s, avg: 141.94 MB/s || "
    "DOWN: 256.19 MB transferred (12.81% complete) | Speed: min: 0.11 MB/s, max: 433.30 MB/s, avg: 123.19 MB/s"
)

MESSAGE2 = (
    "2025-02-14 07:18:57,982 INFO: UP: 2000.00 MB transferred (100.00% complete) | Speed: min: 0.00 MB/s, max: 0.00 MB/s, avg: 0.00 MB/s || "
    "DOWN: 2000.00 MB transferred (100.00% complete) | Speed: min: 0.00 MB/s, max: 0.00 MB/s, avg: 0.00 MB/s"
)

# Expected tuples from parse_transfer_metrics:
EXPECTED1 = (447.69, 22.38, 74.58, 177.97, 141.94, 256.19, 12.81, 0.11, 433.30, 123.19)
EXPECTED2 = (2000.00, 100.00, 0.00, 0.00, 0.00, 2000.00, 100.00, 0.00, 0.00, 0.00)


class TestTransferMetricsParsing(unittest.TestCase):
    def test_parse_transfer_metrics_message1(self):
        """Test parse_transfer_metrics with the first sample message."""
        result = parse_transfer_metrics(MESSAGE1)
        self.assertIsNotNone(result, "Parsing should return a tuple, not None.")
        # Check that the result tuple has the expected length.
        self.assertEqual(
            len(result),
            len(EXPECTED1),
            f"Expected result tuple length to be {len(EXPECTED1)} but got {len(result)}",
        )
        # Compare each float value using almost equal, to handle minor float imprecisions.
        for expected_value, result_value in zip(EXPECTED1, result):
            self.assertAlmostEqual(
                expected_value,
                result_value,
                places=2,
                msg=f"Expected {expected_value} but got {result_value}",
            )

    def test_parse_transfer_metrics_message2(self):
        """Test parse_transfer_metrics with the second sample message."""
        result = parse_transfer_metrics(MESSAGE2)
        self.assertIsNotNone(result, "Parsing should return a tuple, not None.")
        # Check that the result tuple has the expected length.
        self.assertEqual(
            len(result),
            len(EXPECTED2),
            f"Expected result tuple length to be {len(EXPECTED2)} but got {len(result)}",
        )
        for expected_value, result_value in zip(EXPECTED2, result):
            self.assertAlmostEqual(
                expected_value,
                result_value,
                places=2,
                msg=f"Expected {expected_value} but got {result_value}",
            )

    def test_dataframe_parsing(self):
        """
        Test that a temporary log file containing our two sample messages is parsed
        correctly into a pandas DataFrame with the right metric values and file details.
        """
        # Create a temporary directory and file with a valid log filename.
        with tempfile.TemporaryDirectory() as temp_dir:
            filename = "cst_baseline_1c_1mb.log"
            filepath = os.path.join(temp_dir, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(MESSAGE1 + "\n")
                f.write(MESSAGE2 + "\n")

            # Load the logs from the temporary file.
            df = load_logs([filepath])
            # Only two lines should have transfer events.
            df_transfer = df[df["event"] == "transfer"]
            self.assertEqual(
                len(df_transfer), 2, "Expected 2 transfer events in the DataFrame."
            )

            # Check that the file name and parsed filename details are set.
            for _, row in df_transfer.iterrows():
                self.assertEqual(row["file"], filename)
                self.assertEqual(row["mode"], "baseline")
                self.assertEqual(row["concurrency"], "1c")
                self.assertEqual(row["transfersize"], "1mb")

            # Now check the metrics for each row.
            # Row order is the order in the file.
            row1 = df_transfer.iloc[0]
            self.assertAlmostEqual(row1["up_mb"], EXPECTED1[0], places=2)
            self.assertAlmostEqual(row1["up_pct"], EXPECTED1[1], places=2)
            self.assertAlmostEqual(row1["up_min"], EXPECTED1[2], places=2)
            self.assertAlmostEqual(row1["up_max"], EXPECTED1[3], places=2)
            self.assertAlmostEqual(row1["up_avg"], EXPECTED1[4], places=2)
            self.assertAlmostEqual(row1["down_mb"], EXPECTED1[5], places=2)
            self.assertAlmostEqual(row1["down_pct"], EXPECTED1[6], places=2)
            self.assertAlmostEqual(row1["down_min"], EXPECTED1[7], places=2)
            self.assertAlmostEqual(row1["down_max"], EXPECTED1[8], places=2)
            self.assertAlmostEqual(row1["down_avg"], EXPECTED1[9], places=2)

            row2 = df_transfer.iloc[1]
            self.assertAlmostEqual(row2["up_mb"], EXPECTED2[0], places=2)
            self.assertAlmostEqual(row2["up_pct"], EXPECTED2[1], places=2)
            self.assertAlmostEqual(row2["up_min"], EXPECTED2[2], places=2)
            self.assertAlmostEqual(row2["up_max"], EXPECTED2[3], places=2)
            self.assertAlmostEqual(row2["up_avg"], EXPECTED2[4], places=2)
            self.assertAlmostEqual(row2["down_mb"], EXPECTED2[5], places=2)
            self.assertAlmostEqual(row2["down_pct"], EXPECTED2[6], places=2)
            self.assertAlmostEqual(row2["down_min"], EXPECTED2[7], places=2)
            self.assertAlmostEqual(row2["down_max"], EXPECTED2[8], places=2)
            self.assertAlmostEqual(row2["down_avg"], EXPECTED2[9], places=2)


if __name__ == "__main__":
    unittest.main()
