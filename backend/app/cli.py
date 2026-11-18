"""Local command-line tool (runs on the analyst's machine; no network exposure).

    python -m app.cli snapshots
    python -m app.cli create-snapshot "Corp AD - Nov 2026" [--sample]
    python -m app.cli import <snapshot-id> <file.zip|.json|.csv>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sqlalchemy import select

from app.core.config import get_settings
from app.core.errors import AegisError
from app.core.jobs import CancellationToken
from app.core.logging import configure_logging
from app.core.resources import ResourceManager
from app.db.session import Database
from app.ingestion.service import ImportService
from app.models import Snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis", description="AEGIS local administration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("snapshots", help="list snapshots")
    create = sub.add_parser("create-snapshot", help="create an empty snapshot")
    create.add_argument("name")
    create.add_argument("--description")
    create.add_argument("--sample", action="store_true", help="mark as synthetic sample data")
    imp = sub.add_parser("import", help="import a data file into a snapshot")
    imp.add_argument("snapshot_id", type=int)
    imp.add_argument("file", type=Path)
    args = parser.parse_args(argv)

    settings = get_settings()
    configure_logging("WARNING", extra_secrets=[settings.secret_key.get_secret_value()])
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(settings.database_url)
    db.migrate()
    service = ImportService(db, settings, ResourceManager(settings))
    try:
        if args.command == "snapshots":
            with db.session() as s:
                for snap in s.scalars(select(Snapshot).order_by(Snapshot.id)):
                    stats = snap.stats or {}
                    print(f"{snap.id:>4}  {snap.status:<9} {'[sample] ' if snap.is_sample else ''}{snap.name}  "
                          f"objects={stats.get('objects_total', 0)} "
                          f"relationships={stats.get('relationships_total', 0)}")
        elif args.command == "create-snapshot":
            sid = service.create_snapshot(args.name, description=args.description, is_sample=args.sample)
            print(f"Created snapshot {sid}")
        elif args.command == "import":
            if not args.file.is_file():
                print(f"File not found: {args.file}", file=sys.stderr)
                return 2

            def progress(fraction: float, message: str) -> None:
                print(f"\r{message}: {fraction:6.1%}", end="", file=sys.stderr, flush=True)

            result = service.import_file(args.snapshot_id, args.file, args.file.name,
                                         token=CancellationToken(settings.job_timeout_seconds * 10),
                                         progress=progress)
            print(file=sys.stderr)
            print(json.dumps({"status": result.status, "import_job_id": result.import_job_id, **result.summary},
                             indent=2, default=str))
            return 0 if result.status in ("succeeded", "partial") else 1
    except AegisError as exc:
        print(f"\nError ({exc.code}): {exc.message}", file=sys.stderr)
        return 1
    finally:
        db.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
