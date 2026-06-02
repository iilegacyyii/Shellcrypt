from rich.logging import RichHandler
import logging
import os

DEBUG = False

log_path = "logs"
debug_path = "logs/debug_logs.log"
session_path = "logs/session_logs.log"
if not os.path.exists(log_path):
    os.mkdir(log_path)

if not os.path.exists(debug_path):
    with open(debug_path, 'w', encoding='utf-8'): pass

if not os.path.exists(session_path):
    with open(session_path, 'w', encoding='utf-8'): pass

logging.basicConfig(
    level="DEBUG",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        RichHandler(rich_tracebacks=True),
        logging.FileHandler(debug_path, mode='a', encoding="utf-8"),
        logging.FileHandler(session_path, mode='w', encoding="utf-8"),
    ],
)

logger = logging.getLogger("rich")


class Log:
    """Handles all styled terminal output."""
    def __init__(self):
        pass

    @staticmethod
    def logSuccess(msg: str):
        """Logs msg to the terminal with a green [+] appended. Used to show task success."""
        return logger.debug(f"[+] {msg}")

    @staticmethod
    def logInfo(msg: str):
        """Logs msg to the terminal with a blue [*] appended. Used to show task status / info."""
        return logger.info(f"[!] {msg}")

    @staticmethod
    def logDebug(msg: str):
        """Logs msg to the terminal with a magenta [debug] appended. Used for debug info."""
        if DEBUG:
            return logger.debug(f"[+] {msg}")

    @staticmethod
    def logError(msg: str):
        """Logs msg to the terminal with a red [!] appended. Used for error messages."""
        return logger.error(f"[-] {msg}")

    @staticmethod
    def LogException(msg: str):
        """Logs msg to the terminal with a red [!!] appended. Used to show error messages."""
        return logger.exception(f"[!!] {msg}")
