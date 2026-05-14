from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TextIO


LOGGER_NAME = "rules_farmer"


class _ExecutionFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if getattr(record, "stage", False):
            timestamp = self.formatTime(record, self.datefmt)
            return f"{timestamp} {record.getMessage()}"
        return super().format(record)


class _FlushFileHandler(logging.FileHandler):
    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


def configure_execution_logging(
    log_path: str | Path = "output.log",
    stream: TextIO | None = None,
    level: int = logging.INFO,
    force: bool = True,
) -> Path:
    destination = Path(log_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(LOGGER_NAME)
    if force:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()

    formatter = _ExecutionFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(stream or sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    file_handler = _FlushFileHandler(destination, mode="a", encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.setLevel(level)
    logger.propagate = False
    logger.info("Execution logging started log_path=%s", destination)
    return destination


def log_stage(message: str) -> None:
    logging.getLogger(LOGGER_NAME).info(format_stage(message), extra={"stage": True})


def format_stage(message: str) -> str:
    return f"<------------- {message.strip().upper()} ------------->"
