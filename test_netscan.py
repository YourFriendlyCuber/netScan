import argparse
import ipaddress
import logging
import logging.config
import statistics
import subprocess
import sys
import time
from pathlib import Path

import psutil

python = sys.executable

SUPPORTED_LANGUAGES = {
    ".py": {
        "command_prefix": [python],
    }
}

logging_config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(message)s"},
    },
    "handlers": {
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "stream": sys.stdout,
        },
        "file": {
            "level": "DEBUG",
            "class": "logging.FileHandler",
            "formatter": "standard",
            "filename": "results.log",
            "mode": "w",
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "DEBUG",
    },
}

logging.config.dictConfig(logging_config)
logger = logging.getLogger(__name__)


class Process:
    """
    A class to manage a process, including starting and stopping the process.

    Attributes:
            path (Path): The path to the program.
            command (list): The command to run the process.
            find_port (bool): Whether port detection is enabled.
            show_output (bool): Whether to show the program's output.
            process (psutil.Popen): The process object.
            port (int): The port number the process is listening on, if applicable.
    """

    def __init__(self, path: Path, command: list, find_port: bool = False, show_output: bool = False):
        self.path = path
        self.command = command
        self.find_port = find_port
        self.show_output = show_output
        self.process = None
        self.port = None

    @classmethod
    def from_dict(cls, config: dict):
        """Creates a Process instance from a configuration dictionary."""
        path = config.get("program")
        command = config.get("command")
        find_port = config.get("find_port", False)
        show_output = config.get("show_output", False)

        if not isinstance(path, Path):
            raise TypeError("Expected 'program' to be a Path object")
        if not isinstance(command, list):
            raise TypeError("Expected 'command' to be a list")
        if not isinstance(find_port, bool):
            raise TypeError("Expected 'find_port' to be a boolean")
        if not isinstance(show_output, bool):
            raise TypeError("Expected 'show_output' to be a boolean")

        return cls(path, command, find_port, show_output)

    def start(self):
        """Starts the process."""
        stdout = sys.stdout if self.show_output else subprocess.DEVNULL
        stderr = sys.stderr if self.show_output else subprocess.DEVNULL

        self.process = psutil.Popen(
            self.command,
            stdout=stdout,
            stderr=stderr,
            text=True,
        )

        if self.find_port:
            # Waits for port to bind
            time.sleep(0.5)
            self.port = get_port(self.process.pid)
            if self.port is None:
                self.terminate()
                raise RuntimeError("Could not get port number. Another process might be using the port")

    def terminate(self, timeout: int = 2):
        """Terminates the process."""
        try:
            self.process.terminate()
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
        except Exception as e:
            logger.error(f"Failed to terminate the process: {e}")

    def wait(self, timeout: int = 2):
        """Waits for the process to complete within the specified timeout period."""
        try:
            self.process.wait(timeout=timeout)
            return True
        except psutil.TimeoutExpired:
            return False

    def __enter__(self):
        """Allows the process to be used as a context manager."""
        self.start()
        return self

    def __exit__(self, type, value, traceback):
        """Ensures the process is terminated when the context is exited."""
        self.terminate()


def get_port(pid: int, retries: int = 2, delay: float = 1) -> int | None:
    """Retrieves the port number a process is listening on."""
    for _ in range(1, retries + 1):
        try:
            process = psutil.Process(pid)
            for conn in process.net_connections():
                if conn.status == psutil.CONN_LISTEN:
                    return conn.laddr.port
        except psutil.NoSuchProcess:
            logger.error(f"[get_port] No process found with pid: {pid}")
            return None
        logger.debug(f"[get_port] Retrying in {delay} seconds...")
        time.sleep(delay)
    logger.error(f"[get_port] Failed to get port after {retries} attempts")


def measure_netscan(process_config: dict, timeout: int = 16, repeat: int = 5):
    """
    Measures the performance of a network scanner program.

    Args:
        process_config (dict): Configuration dictionary for the process.
        timeout (int): Timeout duration in seconds to wait for the process to finish.
        repeat (int): Number of times to repeat the measurement.

    Returns:
        average_time (float): The average elapsed times.
    """
    elapsed_times = []
    program = Process.from_dict(process_config)

    for run in range(1, repeat + 1):
        program.start()
        start = time.time()

        if not program.wait(timeout=timeout):
            program.terminate()
            logger.error("Timeout expired. If the program needs more time, increase the timeout in the main function")
            return None

        end = time.time()
        elapsed_time = end - start
        elapsed_times.append(end - start)
        logger.info(f"Run {run} took {elapsed_time:.6f} seconds")
        time.sleep(1)

    return statistics.mean(elapsed_times)


def validate_program(program: Path) -> Path | None:
    """
    Validates the main program file.

    Returns:
        program (Path): The validated program, or None if the validation fails.
    """
    if not program.is_file():
        logger.error(f"Error: {program} does not exist or is not a file")
        return None

    if program.stem != "main":
        logger.error("Error: The program must be called 'main'")
        return None

    if program.suffix not in SUPPORTED_LANGUAGES:
        logger.error(f"Error: The file extension {program.suffix} is not supported yet")
        logger.error(f"Supported languages are: {', '.join(SUPPORTED_LANGUAGES.keys())}")
        return None

    return program


def validate_network(network: str) -> str | None:
    """
    Validates the network is given in CIDR notation (e.g., '192.168.1.0/24').

    Returns:
        network (str | None): The validated network, or None if the validation fails.
    """
    try:
        ipaddress.IPv4Network(network)
        return network
    except ValueError as e:
        logger.error(f"Error: Invalid network: {network}")
        logger.error(e)
        return None


def main(program: Path, network: str):
    """
    Main function to measure Netscan performance.

    This function measures the performance of the Netscan program using a given network.
    A timeout is used to ensure the script does not hang in case the program does not stop by itself.
    If the program needs more time to finish, the timeout can be increased.

    Args:
        program (Path): The path to the Netscan program.
        network (str): The network to scan in CIDR notation (e.g., '192.168.1.0/24').
    """
    command_prefix = SUPPORTED_LANGUAGES[program.suffix]["command_prefix"]

    process_config = {
        "program": program,
        "command": command_prefix + [program, network],
        # "show_output": True,
    }

    logger.info(f"{"-" * 80}")
    avg_netscan_time = measure_netscan(process_config, timeout=16)

    if avg_netscan_time is None:
        avg_netscan_time = float("inf")

    # ---------------------------------------
    # Measure             | Average Time (s)
    # ---------------------------------------
    # netscan             | 3.366740

    logger.info(f"{'-' * 80}")
    logger.info(f"{'Measure':<20} | {'Average Time (s)':<20}")
    logger.info(f"{'-' * 80}")
    logger.info(f"{'netscan':<20} | {avg_netscan_time:<20.6f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Specify the main program file.")
    parser.add_argument("program", help="The path to the main program file.")
    parser.add_argument("network", help="The network to scan (e.g. 192.168.1.0/24).")
    args = parser.parse_args()

    program = validate_program(Path(args.program))
    network = validate_network(args.network)

    if program is None or network is None:
        sys.exit(1)

    logger.info(f"\n{program.absolute()}")
    logger.info(f"\n{network}\n")

    main(program, network)
