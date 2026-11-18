"""Remaining BloodHound relationship types and the command-line tool."""

import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import aliased

from app.db.session import Database
from app.ingestion.service import ImportService
from app.models import AdEdge, AdObject
from tests.bh_builders import DOM, bh_file, computer, domain, sharphound_zip, sid, user, write_json


@pytest.fixture
def db(settings):
    database = Database(settings.database_url)
    database.migrate()
    yield database
    database.dispose()


@pytest.fixture
def service(db, settings, resources):
    return ImportService(db, settings, resources)


def edges_of(db, snapshot_id):
    src, dst = aliased(AdObject), aliased(AdObject)
    with db.session() as s:
        return {tuple(r) for r in s.execute(
            select(src.object_id, AdEdge.kind, dst.object_id).join(src, AdEdge.src_object_pk == src.id)
            .join(dst, AdEdge.dst_object_pk == dst.id).where(AdEdge.snapshot_id == snapshot_id))}


def test_delegation_sidhistory_sqladmin(tmp_path, service, db):
    u = user(1101, "SVC_WEB", hasspn=True)
    u["AllowedToDelegate"] = [{"ObjectIdentifier": sid(1301), "ObjectType": "Computer"}, sid(1302)]  # v6 + legacy
    u["HasSIDHistory"] = [{"ObjectIdentifier": sid(500), "ObjectType": "User"}]
    u["SPNTargets"] = [{"ComputerSID": sid(1303), "Port": 1433, "Service": "SQLAdmin"},
                       {"ComputerSID": sid(1304), "Port": 80, "Service": "HTTP"}]
    snap = service.create_snapshot("s")
    service.import_file(snap, write_json(tmp_path / "users.json", bh_file("users", [u])), "users.json")
    e = edges_of(db, snap)
    assert {(sid(1101), "AllowedToDelegate", sid(1301)), (sid(1101), "AllowedToDelegate", sid(1302)),
            (sid(1101), "HasSIDHistory", sid(500)), (sid(1101), "SQLAdmin", sid(1303))} <= e
    assert not any(dst == sid(1304) for _, _, dst in e)  # only the SQLAdmin service creates an edge


def test_user_rights_and_extra_local_groups(tmp_path, service, db):
    c = computer(1301, "WS01")
    c["UserRights"] = [{"Privilege": "SeRemoteInteractiveLogonRight",
                        "Results": [{"ObjectIdentifier": sid(1201), "ObjectType": "Group"}], "Collected": True},
                       {"Privilege": "SeBackupPrivilege", "Results": [{"ObjectIdentifier": sid(1202)}]}]
    c["LocalGroups"].append({"ObjectIdentifier": f"{sid(1301)}-580", "Name": "REMOTE MANAGEMENT USERS@WS01",
                             "Results": [{"ObjectIdentifier": sid(1203), "ObjectType": "User"}]})
    c["LocalGroups"].append({"ObjectIdentifier": f"{sid(1301)}-562", "Name": "DISTRIBUTED COM USERS@WS01",
                             "Results": [{"ObjectIdentifier": sid(1204), "ObjectType": "User"}]})
    snap = service.create_snapshot("s")
    service.import_file(snap, write_json(tmp_path / "computers.json", bh_file("computers", [c])), "computers.json")
    e = edges_of(db, snap)
    assert (sid(1201), "CanRDP", sid(1301)) in e
    assert (sid(1203), "CanPSRemote", sid(1301)) in e
    assert (sid(1204), "ExecuteDCOM", sid(1301)) in e
    assert not any(src == sid(1202) for src, _, _ in e)  # unmapped privilege ignored


@pytest.mark.parametrize("direction,expected", [
    ("Inbound", {(DOM, "TrustedBy", "S-1-5-21-9")}),
    (3, {(DOM, "TrustedBy", "S-1-5-21-9"), ("S-1-5-21-9", "TrustedBy", DOM)}),
    (0, set()),
])
def test_trust_directions(tmp_path, service, db, direction, expected):
    trust = {"TargetDomainSid": "S-1-5-21-9", "TargetDomainName": "OTHER.LOCAL", "TrustDirection": direction}
    snap = service.create_snapshot("s")
    service.import_file(snap, write_json(tmp_path / "domains.json", bh_file("domains", [domain(trusts=[trust])])),
                        "domains.json")
    trusts = {e for e in edges_of(db, snap) if e[1] == "TrustedBy"}
    assert trusts == expected


def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    from app.cli import main
    from app.core.config import get_settings

    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "cli-data"))
    monkeypatch.setenv("AEGIS_ENV", "test")
    get_settings.cache_clear()
    try:
        assert main(["create-snapshot", "Lab AD", "--sample"]) == 0
        assert "Created snapshot 1" in capsys.readouterr().out
        assert main(["import", "1", str(sharphound_zip(tmp_path / "lab.zip"))]) == 0
        out = capsys.readouterr().out
        assert json.loads(out)["status"] == "succeeded"
        assert main(["snapshots"]) == 0
        listing = capsys.readouterr().out
        assert "[sample] Lab AD" in listing and "objects=" in listing
        assert main(["import", "1", str(tmp_path / "missing.zip")]) == 2
        assert main(["import", "99", str(tmp_path / "lab.zip")]) == 1
        assert "not_found" in capsys.readouterr().err
    finally:
        get_settings.cache_clear()
