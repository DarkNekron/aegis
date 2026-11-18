"""Ingestion benchmark: generates a synthetic SharpHound-style ZIP and measures import time and peak RSS.

Usage (from backend/):
    .venv\\Scripts\\python.exe ..\\scripts\\bench_ingestion.py --users 20000 --workdir <empty temp dir>

All data is synthetic. Results are printed as JSON so they can be recorded in docs/BENCHMARKS.md.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import threading
import time
import zipfile
from pathlib import Path

import psutil

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))

DOM = "S-1-5-21-111-222-333"


def sid(rid: int) -> str:
    return f"{DOM}-{rid}"


def generate(path: Path, users: int, seed: int = 7) -> dict[str, int]:
    rng = random.Random(seed)  # noqa: S311 - deterministic synthetic test data, not security-sensitive
    groups, computers = max(10, users // 7), max(5, users // 4)
    user_rids = list(range(10_000, 10_000 + users))
    group_rids = list(range(100_000, 100_000 + groups))
    comp_rids = list(range(200_000, 200_000 + computers))

    def meta(t, n):
        return {"methods": 46067, "type": t, "count": n, "version": 6}

    user_items = [{
        "ObjectIdentifier": sid(r), "PrimaryGroupSID": sid(513), "AllowedToDelegate": [], "HasSIDHistory": [],
        "SPNTargets": [], "Aces": [], "IsDeleted": False,
        "Properties": {"name": f"USER{r}@LAB.LOCAL", "domain": "LAB.LOCAL", "enabled": rng.random() > 0.1,
                       "hasspn": rng.random() < 0.02, "description": "synthetic benchmark user",
                       "lastlogon": 1730000000 + r, "pwdlastset": 1720000000},
    } for r in user_rids]
    group_items = [{
        "ObjectIdentifier": sid(g), "Properties": {"name": f"GROUP{g}@LAB.LOCAL", "domain": "LAB.LOCAL"},
        "Members": [{"ObjectIdentifier": sid(m), "ObjectType": "User"} for m in rng.sample(user_rids, 15)],
        "Aces": [{"PrincipalSID": sid(rng.choice(user_rids)), "PrincipalType": "User",
                  "RightName": rng.choice(["GenericAll", "GenericWrite", "WriteDacl", "AddMember"]),
                  "IsInherited": False} for _ in range(3)],
        "IsDeleted": False,
    } for g in group_rids]
    comp_items = [{
        "ObjectIdentifier": sid(c), "PrimaryGroupSID": sid(515), "AllowedToDelegate": [], "AllowedToAct": [],
        "Properties": {"name": f"HOST{c}.LAB.LOCAL", "domain": "LAB.LOCAL", "enabled": True,
                       "operatingsystem": "Windows 11 Enterprise"},
        "Sessions": {"Results": [{"UserSID": sid(u), "ComputerSID": sid(c)} for u in rng.sample(user_rids, 2)],
                     "Collected": True},
        "LocalGroups": [{"ObjectIdentifier": f"{sid(c)}-544", "Name": "ADMINISTRATORS",
                         "Results": [{"ObjectIdentifier": sid(g), "ObjectType": "Group"}
                                     for g in rng.sample(group_rids, 2)], "Collected": True}],
        "Aces": [], "IsDeleted": False,
    } for c in comp_rids]

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bench_users.json", json.dumps({"data": user_items, "meta": meta("users", users)}))
        zf.writestr("bench_groups.json", json.dumps({"data": group_items, "meta": meta("groups", groups)}))
        zf.writestr("bench_computers.json", json.dumps({"data": comp_items, "meta": meta("computers", computers)}))
    return {"users": users, "groups": groups, "computers": computers}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=20_000)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--phase", choices=["generate", "import", "both"], default="both",
                        help="run generate and import in separate processes for a clean peak-RSS figure")
    args = parser.parse_args()
    args.workdir.mkdir(parents=True, exist_ok=True)

    vm = psutil.virtual_memory()
    if vm.available < 1024 * 1024 * 1024:
        sys.exit(f"Refusing to run: only {vm.available // 2**20} MB RAM free (need 1024 MB).")

    zpath = args.workdir / "bench.zip"
    gen_seconds = 0.0
    shape: dict[str, int] = {"users": args.users}
    if args.phase in ("generate", "both"):
        t0 = time.perf_counter()
        shape = generate(zpath, args.users)
        gen_seconds = time.perf_counter() - t0
        if args.phase == "generate":
            print(json.dumps({"generated": str(zpath), "shape": shape, "seconds": round(gen_seconds, 1)}))
            return

    from app.core.config import Settings
    from app.core.jobs import CancellationToken
    from app.core.resources import ResourceManager
    from app.db.session import Database
    from app.ingestion.service import ImportService

    settings = Settings(env="test", data_dir=args.workdir / "data", _env_file=None)
    db = Database(settings.database_url)
    db.migrate()
    service = ImportService(db, settings, ResourceManager(settings))
    snap = service.create_snapshot("benchmark")

    proc = psutil.Process()
    baseline = proc.memory_info().rss
    peak = [baseline]
    stop = threading.Event()

    def sample() -> None:
        while not stop.is_set():
            peak[0] = max(peak[0], proc.memory_info().rss)
            time.sleep(0.05)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    t1 = time.perf_counter()
    result = service.import_file(snap, zpath, "bench.zip", token=CancellationToken(3600))
    import_seconds = time.perf_counter() - t1
    stop.set()
    sampler.join()
    db.dispose()

    s = result.summary
    print(json.dumps({
        "shape": shape,
        "zip_mb": round(zpath.stat().st_size / 2**20, 1),
        "uncompressed_mb": round(sum(i.file_size for i in zipfile.ZipFile(zpath).infolist()) / 2**20, 1),
        "generate_seconds": round(gen_seconds, 1),
        "import_seconds": round(import_seconds, 1),
        "objects_inserted": s["objects_inserted"],
        "placeholders_created": s["placeholders_created"],
        "relationships_inserted": s["relationships_inserted"],
        "status": result.status,
        "rss_baseline_mb": baseline // 2**20,
        "rss_peak_mb": peak[0] // 2**20,
        "rss_import_delta_mb": (peak[0] - baseline) // 2**20,
        "db_mb": round((args.workdir / "data" / "aegis.db").stat().st_size / 2**20, 1),
    }, indent=2))


if __name__ == "__main__":
    main()
