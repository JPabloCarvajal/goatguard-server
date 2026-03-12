"""
Zeek execution wrapper for GOATGuard server.

Runs Zeek inside a Docker container to process PCAP files.
Each invocation processes one PCAP file and generates log files
(conn.log, dns.log, ssl.log, weird.log) in an output directory.

Zeek runs in Docker because it is a Linux-native tool. This
allows the server to run on Windows during development while
still leveraging Zeek's analysis capabilities.

Requirements: Part of Sprint 3 (PCAP analysis pipeline)
"""

import logging
import subprocess
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

class ZeekRunner:
    """Executes Zeek via Docker to analyze PCAP files.

    For each PCAP file, creates a temporary output directory,
    runs Zeek inside a container, and returns the path to the
    generated log files.

    Args:
        output_base_dir: Base directory where Zeek output folders
                         are created. Each PCAP gets its own subfolder.
    """

    def __init__(self, output_base_dir: str = "zeek_output") -> None:
        self.output_base_dir = Path(output_base_dir)
        self.output_base_dir.mkdir(parents=True, exist_ok=True)

    def process_pcap(self, pcap_path: str) -> Path:
        """Run Zeek on a PCAP file and return the log directory.

        Creates a unique output directory per PCAP file using the
        filename as identifier. Runs Zeek in a Docker container
        with the PCAP mounted as input and the output directory
        mounted for log collection.

        Args:
            pcap_path: Path to the PCAP file to analyze.

        Returns:
            Path to the directory containing Zeek's log files.

        Raises:
            RuntimeError: If Zeek execution fails.
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise RuntimeError(f"PCAP file not found: {pcap_path}")

        # Create output directory named after the PCAP file
        # capture_20260310_164315.pcap -> zeek_output/capture_20260310_164315/
        log_dir_name = pcap_path.stem
        log_dir = self.output_base_dir / log_dir_name

        # Clean previous run if exists
        if log_dir.exists():
            shutil.rmtree(log_dir)
        log_dir.mkdir(parents=True)

        # Build Docker command
        pcap_absolute = pcap_path.resolve()
        log_dir_absolute = log_dir.resolve()

        command = [
            "docker", "run", "--rm",
            "-v", f"{pcap_absolute.parent}:/data",
            "-v", f"{log_dir_absolute}:/output",
            "-w", "/output",
            "zeek/zeek",
            "zeek", "-r", f"/data/{pcap_absolute.name}",
        ]

        logger.info(f"Running Zeek on {pcap_path.name}...")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                logger.error(f"Zeek failed: {result.stderr}")
                raise RuntimeError(f"Zeek exit code {result.returncode}: {result.stderr}")

        except subprocess.TimeoutExpired:
            logger.error(f"Zeek timed out processing {pcap_path.name}")
            raise RuntimeError("Zeek timed out after 120 seconds")

        # Verify output
        conn_log = log_dir / "conn.log"
        if not conn_log.exists():
            logger.warning(f"Zeek produced no conn.log for {pcap_path.name}")

        log_count = len(list(log_dir.glob("*.log")))
        logger.info(f"Zeek finished: {log_count} log files in {log_dir}")

        return log_dir

if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    logging.basicConfig(level=logging.DEBUG)

    runner = ZeekRunner(output_base_dir="zeek_output")

    # Pick the first PCAP available
    pcap_dir = Path("pcap_output")
    pcap_files = sorted(pcap_dir.glob("*.pcap"))

    if not pcap_files:
        print("No PCAP files found in pcap_output/")
        sys.exit(1)

    pcap_file = pcap_files[0]
    print(f"Processing: {pcap_file}")

    log_dir = runner.process_pcap(str(pcap_file))
    print(f"Logs in: {log_dir}")
    print(f"Files: {[f.name for f in log_dir.glob('*.log')]}")