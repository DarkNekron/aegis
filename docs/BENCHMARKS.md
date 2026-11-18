# AEGIS — Benchmarks

Only measured results are recorded here. Each entry states the hardware, dataset and command so it can be reproduced.

**Machine:** Dell G15 5530, Intel i7-13650HX, 16 GB DDR5, NVMe SSD, Windows 11. VS Code and Chrome were running, as in a
normal working session. Python 3.12.10, SQLite 3.49.1 (WAL), pure-Python SQLAlchemy (see DEPENDENCIES.md).

## Ingestion

| Date | Dataset | Upload | Import time | Peak RSS increase during import | Result |
|---|---|---|---|---|---|
| 2026-11-18 | Synthetic SharpHound v6 ZIP: 20,000 users, 2,857 groups, 5,000 computers | 0.6 MB ZIP / 15.9 MB JSON | **9.4 s** (11.3 s on a second run) | **+14 MB** (73 → 87 MB) | 27,857 objects, 96,426 relationships, 2 placeholders; database file 58.7 MB |

Method: `scripts/bench_ingestion.py --phase generate`, then `--phase import` in a **fresh process**, so the
generator's memory is not counted. RSS is sampled every 50 ms. The relationship mix: 15 members per group, 3 ACEs per
group, 2 sessions and 2 admin groups per computer, plus a primary group for every principal.

Interpretation: memory use is flat with respect to input size (streaming parse, batched Core inserts, set-based
SQL finalisation). Run time scales with relationship count and is dominated by SQLite inserts.

```powershell
cd backend
.venv\Scripts\python.exe ..\scripts\bench_ingestion.py --users 20000 --workdir <empty dir> --phase generate
.venv\Scripts\python.exe ..\scripts\bench_ingestion.py --users 20000 --workdir <same dir> --phase import
```

## Graph construction

| Date | Dataset | Nodes / edges | Build time | Graph memory retained | Peak RSS increase |
|---|---|---|---|---|---|
| 2026-11-18 | The 20k-user ingestion benchmark database above | 27,859 / 96,426 | **0.89 s** | **87 MB** | +90 MB (81 → 171 MB) |

Method: `scripts/bench_ingestion.py --phase graph` in a fresh process against the database produced by
`--phase import`. "Retained" is RSS after the build minus RSS before it, with the graph still referenced.

**Calibration consequence:** the original planning estimate (700 B/node, 500 B/edge) predicted 64 MB, which was
35% too low. `app/core/resources.py` now uses 1,100 B/node and 700 B/edge, predicting 98 MB for this dataset.
At the configured maximum graph size (150k nodes, 1.5M edges) the estimate is about 1.2 GB, which is why
`AEGIS_GRAPH_CACHE_SIZE` defaults to 1 on this 16 GB laptop.

## Full pipeline: import, graph and attack-path analysis

Dataset: `corp-medium` regenerated with 20,000 noise users (`scripts/bench_analysis.py --noise-users 20000`):
27,638 objects, 114,480 relationships, 19,022 starting identities, 24 planted chains. One fresh process,
default settings (depth 10, 5 alternatives per source).

| Date | Import | Graph build | Analysis (paths, alternatives, min-cut, centrality) | Peak RSS | Correctness |
|---|---|---|---|---|---|
| 2026-11-18 (first run) | 19.1 s | 2.69 s | 2.55 s | 272 MB | 33/33 exposed users, hops match ground truth |
| 2026-11-18 (after GC fix) | 17.8 s | **0.67 s** | **0.67 s** | **267 MB** | identical results; 222 tests pass |

**Profiling finding:** after the graph exists, building the traversal index allocates about 113k small objects. CPython's
cyclic garbage collector then repeatedly scanned the million-object heap. The objects involved contain no reference
cycles, so collection is paused during bulk construction (`gc_paused()` in `algorithms/index.py`, also used by
the graph builder). Index build went from 2.16 s to 0.62 s and graph build from 2.82 s to 0.67 s, with unchanged
memory and no growth across repeated builds. The searches themselves (reverse Dijkstra, Yen, Edmonds–Karp,
Brandes) take under 10 ms combined on this dataset.
