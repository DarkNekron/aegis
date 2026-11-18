"""Full-pipeline benchmark: generate a scaled corp-medium, import it, build the graph, run the analysis.

    cd backend
    .venv\\Scripts\\python.exe ..\\scripts\\bench_analysis.py --noise-users 20000 --workdir <empty dir>

Prints JSON with timings and RSS (sampled every 50 ms). All data is synthetic.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import threading
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


class PeakRss:
    def __init__(self) -> None:
        self.proc = psutil.Process()
        self.peak = self.proc.memory_info().rss
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            self.peak = max(self.peak, self.proc.memory_info().rss)
            time.sleep(0.05)

    def __enter__(self) -> PeakRss:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join()


def mb(n: int) -> int:
    return n // 2**20


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--noise-users", type=int, default=20_000)
    parser.add_argument("--workdir", type=Path, required=True)
    args = parser.parse_args()
    if psutil.virtual_memory().available < 1536 * 2**20:
        sys.exit("Refusing to run: less than 1.5 GB RAM free.")
    args.workdir.mkdir(parents=True, exist_ok=True)

    spec = importlib.util.spec_from_file_location("gen", ROOT / "scripts" / "generate_sample_data.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    t = time.perf_counter()
    lab, truth = gen.build_corp_medium(noise_users=args.noise_users)
    zpath = args.workdir / "scaled.zip"
    lab.write_zip(zpath, prefix="bench")
    del lab
    generate_s = time.perf_counter() - t

    from app.core.config import Settings
    from app.core.jobs import CancellationToken
    from app.core.resources import ResourceManager
    from app.db.session import Database
    from app.graph_engine.analysis import AnalysisParams, PathAnalyzer
    from app.graph_engine.builder import GraphBuilder
    from app.ingestion.service import ImportService

    settings = Settings(env="test", data_dir=args.workdir / "data", _env_file=None)
    db = Database(settings.database_url)
    db.migrate()
    resources = ResourceManager(settings)
    out: dict = {"noise_users": args.noise_users, "generate_seconds": round(generate_s, 1)}
    proc = psutil.Process()
    with PeakRss() as rss:
        out["rss_start_mb"] = mb(proc.memory_info().rss)
        t = time.perf_counter()
        svc = ImportService(db, settings, resources)
        snap = svc.create_snapshot("bench")
        imported = svc.import_file(snap, zpath, "scaled.zip", token=CancellationToken(3600))
        out["import_seconds"] = round(time.perf_counter() - t, 1)
        out["objects"] = imported.summary["objects_inserted"]
        out["relationships"] = imported.summary["relationships_inserted"]

        t = time.perf_counter()
        graph = GraphBuilder(db, resources).build(snap, token=CancellationToken(600))
        out["graph_seconds"] = round(time.perf_counter() - t, 2)
        out["rss_after_graph_mb"] = mb(proc.memory_info().rss)

        t = time.perf_counter()
        result = PathAnalyzer(graph).run(AnalysisParams.from_settings(settings), token=CancellationToken(600))
        out["analysis_seconds"] = round(time.perf_counter() - t, 2)
        out["analysis_timings"] = result.timings
    out["rss_peak_mb"] = mb(rss.peak)
    out["sources"] = len(graph.sources)
    out["exposed_sources"] = len(result.exposure)
    out["expected_exposed"] = truth["sources_with_paths_count"]
    out["paths"] = len(result.paths)
    out["min_cut_size"] = result.min_cut["size"]
    hops = {graph.name(s): h for s, (h, _) in result.exposure.items()}
    out["ground_truth_hops_match"] = hops == truth["shortest_hops"]
    print(json.dumps(out, indent=2))
    db.dispose()


if __name__ == "__main__":
    main()
