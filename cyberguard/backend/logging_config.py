# backend/logging_config.py
"""Central logging configuration for the CYBERGUARD backend.

Uses the standard library ``logging`` module. Logs are output to STDOUT
and can be captured by the process manager (uvicorn). The format includes
timestamp, log level, module name and the message.
"""

import logging
import sys

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=DATE_FORMAT,
    stream=sys.stdout,
)

# Export a convenience logger for other modules
logger = logging.getLogger("cyberguard")
