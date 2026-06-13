"""
AutoVAPT Logger
Provides colour-coded console output + file logging.
"""

import logging
import sys


# ANSI colour codes
RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"


class ColouredFormatter(logging.Formatter):
    COLOURS = {
        logging.DEBUG:    CYAN,
        logging.INFO:     WHITE,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: BOLD + RED,
    }

    def format(self, record):
        colour = self.COLOURS.get(record.levelno, WHITE)
        record.msg = f"{colour}{record.msg}{RESET}"
        return super().format(record)


def setup_logger(verbose: bool = False, log_file: str = None) -> logging.Logger:
    """
    Create and return the AutoVAPT root logger.
    - Console: coloured, INFO or DEBUG depending on verbose flag.
    - File: plain text, always DEBUG level.
    """
    logger = logging.getLogger("autovapt")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # ── Console handler ───────────────────────────────────────────────────────
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(ColouredFormatter("%(message)s"))
    logger.addHandler(ch)

    # ── File handler ──────────────────────────────────────────────────────────
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(fh)

    return logger
