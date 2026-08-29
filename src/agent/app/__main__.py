"""CLI：python -m app worker | once | version"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from app.config import load_config
from app.observability import setup_logging


def main() -> None:
    parser = argparse.ArgumentParser(prog="nss-ndr-agent", description="深瞳安全分析智能体")
    parser.add_argument("command", choices=["worker", "once", "version"], help="worker=常驻; once=单批消费（调试）; version=版本")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    setup_logging(args.log_level)

    if args.command == "version":
        from app import __version__

        print(f"nss-ndr-agent {__version__}")
        return

    config = load_config()
    if args.command == "once":
        from app.worker import AgentWorker

        async def _once() -> None:
            worker = AgentWorker(config)
            await worker.start()
            processed = await worker.run_once()
            print(json.dumps({"processed": processed, "metrics": worker.metrics.snapshot()}, ensure_ascii=False, indent=2))
            await worker.close()

        asyncio.run(_once())
        return

    from app.worker import run_worker

    run_worker(config)


if __name__ == "__main__":
    sys.exit(main())
