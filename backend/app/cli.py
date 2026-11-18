"""Local command-line tool (runs on the analyst's machine; no network exposure).

    python -m app.cli snapshots
    python -m app.cli create-snapshot "Corp AD - Nov 2026" [--sample]
    python -m app.cli import <snapshot-id> <file.zip|.json|.csv>
    python -m app.cli analyze <snapshot-id> [--top 10]
    python -m app.cli create-user <username> --role admin|analyst|viewer   (password prompted, never an argument)
"""

from __future__ import annotations

import argparse
import getpass
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
from app.graph_engine.cache import GraphCache
from app.graph_engine.service import GraphService
from app.ingestion.service import ImportService
from app.models import Snapshot
from app.security.audit import audit
from app.services.analysis_service import AnalysisService
from app.services.user_service import create_user


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
    ana = sub.add_parser("analyze", help="run an attack-path analysis on a snapshot")
    ana.add_argument("snapshot_id", type=int)
    ana.add_argument("--top", type=int, default=10, help="how many paths to print")
    usr = sub.add_parser("create-user", help="create a user (use this to bootstrap the first administrator)")
    usr.add_argument("username")
    usr.add_argument("--role", choices=["admin", "analyst", "viewer"], required=True)
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
        elif args.command == "create-user":
            password = getpass.getpass("Password: ")
            if password != getpass.getpass("Repeat password: "):
                print("Passwords do not match.", file=sys.stderr)
                return 2
            with db.session() as s:
                user = create_user(s, args.username, password, args.role)
                audit(s, "user_create", "success", username="cli", target_type="user", target_id=user.id,
                      detail={"role": args.role, "new_user": user.username, "via": "cli"})
                print(f"Created {args.role} '{user.username}'.")
        elif args.command == "analyze":
            resources = ResourceManager(settings)
            analyses = AnalysisService(db, settings, GraphService(db, resources, GraphCache(1)))
            analysis_id = analyses.run(args.snapshot_id)
            summary = analyses.get(analysis_id).summary
            env = summary["environment_risk"]
            print(f"Analysis {analysis_id}: environment risk {env['score']} ({env['severity']}); "
                  f"{summary['exposed_sources']} of {summary['sources_total']} identities exposed; "
                  f"{summary['paths_total']} paths {summary['paths_by_severity']}; "
                  f"min cut {summary['min_cut']['size']}")
            _, paths = analyses.list_paths(analysis_id, limit=max(1, min(args.top, 500)))
            for p in paths:
                print(f"  {p.score:6.2f} {p.severity:<8} {p.hops} hop(s) {p.classification:<31} {p.details['summary']}")
    except AegisError as exc:
        print(f"\nError ({exc.code}): {exc.message}", file=sys.stderr)
        return 1
    finally:
        db.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
