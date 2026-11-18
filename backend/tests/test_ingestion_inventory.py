"""AEGIS JSON inventories, CSV inventories and sanitisation helpers."""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import aliased

from app.db.session import Database
from app.ingestion.sanitize import MalformedItem, clean_properties, clean_text, normalize_object_id
from app.ingestion.service import ImportService
from app.models import AdEdge, AdObject
from tests.bh_builders import write_json, write_zip


@pytest.fixture
def db(settings):
    database = Database(settings.database_url)
    database.migrate()
    yield database
    database.dispose()


@pytest.fixture
def service(db, settings, resources):
    return ImportService(db, settings, resources)


def edges(db, snap):
    src, dst = aliased(AdObject), aliased(AdObject)
    with db.session() as s:
        return s.execute(select(src.object_id, AdEdge.kind, dst.object_id, AdEdge.confidence, AdEdge.evidence)
                         .join(src, AdEdge.src_object_pk == src.id).join(dst, AdEdge.dst_object_pk == dst.id)
                         .where(AdEdge.snapshot_id == snap)).all()


INVENTORY = {
    "format": "aegis-inventory", "version": 1, "collected_at": "2026-11-01T10:00:00Z",
    "relationships": [  # deliberately before objects: order must not matter
        {"source": "u-1", "target": "srv-1", "kind": "AdminTo", "confidence": 0.9, "evidence": "CMDB export"},
        {"source": "u-1", "target": "g-1", "kind": "MemberOf"},
        {"source": "u-1", "target": "u-1", "kind": "GenericAll"},
        {"source": "u-2", "target": "g-1", "kind": "Member Of"},
    ],
    "objects": [
        {"id": "u-1", "kind": "user", "name": "alice", "domain": "corp.local", "enabled": True,
         "properties": {"department": "IT", "Bad Key!": 1, "nested": {"x": 1}}},
        {"id": "g-1", "kind": "Group", "name": "IT Admins"},
        {"id": "srv-1", "kind": "computer", "name": "SRV01"},
        {"id": "x-1", "kind": "spaceship", "name": "nope"},
        {"id": "u-3", "kind": "User", "name": "x", "unexpected": True},
    ],
}


def test_aegis_json_inventory(tmp_path, service, db):
    snap = service.create_snapshot("inv")
    result = service.import_file(snap, write_json(tmp_path / "inv.json", INVENTORY), "inv.json")
    assert result.status == "partial"
    e = {(a, k, b): (c, ev) for a, k, b, c, ev in edges(db, snap)}
    assert e[("U-1", "AdminTo", "SRV-1")][0] == 0.9
    assert e[("U-1", "AdminTo", "SRV-1")][1]["note"] == "CMDB export"
    assert ("U-1", "MemberOf", "G-1") in e
    messages = " | ".join(err["message"] for err in result.summary["errors"])
    assert "same object" in messages             # self-relationship
    assert "invalid relationship type" in messages  # "Member Of"
    assert "unknown object kind" in messages     # spaceship
    assert "Extra inputs are not permitted" in messages  # unexpected field
    with db.session() as s:
        alice = s.scalar(select(AdObject).where(AdObject.object_id == "U-1"))
    assert alice.kind == "User" and alice.domain == "CORP.LOCAL"
    assert alice.properties == {"department": "IT"}  # invalid key and nested value dropped


def test_csv_inventory_in_zip_with_bom(tmp_path, service, db):
    objects_csv = "﻿id,kind,name,domain,enabled,department\nu-1,User,alice,corp.local,yes,IT\n" \
                  "srv-1,Computer,SRV01,,,\ng-1,Group,Admins,,,\n"
    rels_csv = "source,target,kind,confidence,evidence\nu-1,srv-1,AdminTo,0.75,local admin\n" \
               "u-1,g-1,MemberOf,,\nu-1,srv-1,AdminTo,not-a-number,\nu-9,srv-1,CanRDP,,,extra\n"
    path = write_zip(tmp_path / "inv.zip", {"rels.csv": rels_csv, "objects.csv": objects_csv})
    snap = service.create_snapshot("csv")
    result = service.import_file(snap, path, "inv.zip")
    assert result.status == "partial"
    assert [err["location"] for err in result.summary["errors"]] == ["row 4", "row 5"]
    e = {(a, k, b): c for a, k, b, c, _ in edges(db, snap)}
    assert e == {("U-1", "AdminTo", "SRV-1"): 0.75, ("U-1", "MemberOf", "G-1"): 0.8}
    with db.session() as s:
        alice = s.scalar(select(AdObject).where(AdObject.object_id == "U-1"))
    assert alice.enabled is True and alice.properties == {"department": "IT"}


def test_csv_with_unknown_header_is_unsupported(tmp_path, service):
    path = tmp_path / "x.csv"
    path.write_text("a,b,c\n1,2,3\n")
    result = service.import_file(service.create_snapshot("s"), path, "x.csv")
    assert result.status == "failed"
    assert "CSV header must contain" in result.summary["files"][0]["error"]


def test_non_utf8_csv(tmp_path, service):
    path = tmp_path / "x.csv"
    path.write_bytes("id,kind,name\nu-1,User,Jos\xe9\n".encode("latin-1"))
    result = service.import_file(service.create_snapshot("s"), path, "x.csv")
    assert result.status == "failed"


@pytest.mark.parametrize("raw,expected", [
    ("s-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-500"),
    ("{2b4f-guid}", "{2B4F-GUID}"),
    ("CORP.LOCAL-S-1-5-32-544", "CORP.LOCAL-S-1-5-32-544"),
])
def test_object_id_normalisation(raw, expected):
    assert normalize_object_id(raw) == expected


@pytest.mark.parametrize("raw", ["", None, "has space", "../etc", "-leading-dash", "x" * 200, "semi;colon"])
def test_object_id_rejects_invalid(raw):
    with pytest.raises(MalformedItem):
        normalize_object_id(raw)


def test_clean_text_and_properties():
    assert clean_text("a​b‮c\x00d") == "abcd"
    assert clean_text("   ") is None
    props = clean_properties({"ok": "v", "list": ["a", {"x": 1}, None, "b"], "nan": float("nan"), "nested": {}},
                             allowed=None)
    assert props == {"ok": "v", "list": ["a", "b"]}
