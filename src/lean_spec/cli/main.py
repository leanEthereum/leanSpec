"""Process entry point for the lean consensus node."""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from lean_spec.log import setup_logging

from .args import parse_args
from .bootstrap import CliValidationError, NodeBootstrap
from .run import run_node

logger = logging.getLogger(__name__)


def main() -> None:
    """Parse CLI arguments and run the node to completion."""
    # Translate the OS argument vector into the typed view.
    args = parse_args()

    # Wire console logging before anything else so early errors are visible.
    setup_logging(args.verbose, args.no_color)

    # Validate cross-field rules and load referenced files.
    try:
        boot = NodeBootstrap.from_cli_args(args)
    except (CliValidationError, FileNotFoundError) as exc:
        logger.error("%s", exc)
        sys.exit(1)

    # Run the node under an event loop until shutdown or a fatal error.
    try:
        asyncio.run(run_node(boot))
    except KeyboardInterrupt:
        # The async runtime cancels tasks on interrupt by itself.
        #
        # The log line only surfaces a graceful-shutdown notice to the operator.
        logger.info("Shutting down...")
    except Exception:
        # Crash path: log the traceback before forcing a non-zero exit.
        logger.exception("Node failed to start")
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(1)
    finally:
        # QUIC keeps background threads holding UDP sockets after loop exit.
        #
        # A hard exit is the only way to release those sockets on shutdown.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)
