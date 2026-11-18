"""BloodHound/SharpHound ingestion: objects, relationship semantics, duplicates and placeholders."""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import aliased

from app.core.errors import ConflictError
from app.db.session import Database
from app.ingestion.service import ImportService
from app.models import AdEdge, AdObject, ImportJob, Snapshot
from tests.bh_builders import (
    DOM,
    ace,
    bh_file,
    group,
    sharphound_zip,
    sid,
    small_domain,
    user,
    write_json,
    write_zip,
)


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
    """Set of (src object_id, kind, dst object_id) for assertions."""
    src, dst = aliased(AdObject), aliased(AdObject)
    with db.session() as s:
        rows = s.execute(select(src.object_id, AdEdge.kind, dst.object_id)
                         .join(src, AdEdge.src_object_pk == src.id).join(dst, AdEdge.dst_object_pk == dst.id)
                         .where(AdEdge.snapshot_id == snapshot_id)).all()
    return {tuple(r) for r in rows}


def objects_of(db, snapshot_id):
    with db.session() as s:
        return {o.object_id: o for o in s.scalars(select(AdObject).where(AdObject.snapshot_id == snapshot_id))}


def test_sharphound_zip_imports_objects_and_correct_relationship_directions(tmp_path, service, db):
    snap = service.create_snapshot("corp")
    result = service.import_file(snap, sharphound_zip(tmp_path / "corp.zip"), "corp.zip")
    assert result.status == "succeeded", result.summary
    e = edges_of(db, snap)

    assert (sid(1101), "GenericAll", sid(1201)) in e          # ACE: principal -> object
    assert (sid(1102), "MemberOf", sid(1201)) in e            # member -> group
    assert (sid(1103), "MemberOf", sid(512)) in e
    assert (sid(1201), "AdminTo", sid(1301)) in e             # local Administrators (RID 544)
    assert (sid(1301), "HasSession", sid(1103)) in e          # computer -> user (credential exposure)
    assert (sid(1104), "AllowedToAct", sid(1301)) in e        # RBCD: principal -> computer
    assert (sid(1101), "MemberOf", sid(513)) in e             # PrimaryGroupSID
    assert ("GPO-DEFAULT-GUID", "GPLink", DOM) in e           # GPO -> linked container
    assert (DOM, "Contains", "OU-USERS-GUID") in e
    # Outbound trust: CORP trusts PARTNER, so PARTNER is trusted by CORP.
    assert ("S-1-5-21-9-9-9", "TrustedBy", DOM) in e
    assert (DOM, "TrustedBy", "S-1-5-21-9-9-9") not in e


def test_object_kinds_names_and_properties(tmp_path, service, db):
    snap = service.create_snapshot("corp")
    service.import_file(snap, sharphound_zip(tmp_path / "corp.zip"), "corp.zip")
    objs = objects_of(db, snap)
    assert objs[sid(1101)].kind == "User" and objs[sid(1101)].name == "ALICE@CORP.LOCAL"
    assert objs[sid(1104)].kind == "ServiceAccount"           # user with SPN
    assert objs[sid(1104)].properties["base_kind"] == "User"
    assert objs[sid(1000)].properties["isdc"] is True
    assert objs[DOM].kind == "Domain" and objs[DOM].domain == "CORP.LOCAL"
    assert objs["OU-USERS-GUID"].kind == "OU"
    assert objs["GPO-DEFAULT-GUID"].kind == "GPO"


def test_contains_from_childobjects_and_containedby_is_deduplicated(tmp_path, service, db):
    snap = service.create_snapshot("corp")
    result = service.import_file(snap, sharphound_zip(tmp_path / "corp.zip"), "corp.zip")
    # ALICE is listed as a child of the OU *and* has ContainedBy -> one edge, one duplicate counted
    assert ("OU-USERS-GUID", "Contains", sid(1101)) in edges_of(db, snap)
    assert result.summary["relationships_duplicate_in_upload"] >= 1


def test_referenced_but_missing_objects_become_typed_placeholders(tmp_path, service, db):
    snap = service.create_snapshot("corp")
    result = service.import_file(snap, sharphound_zip(tmp_path / "corp.zip"), "corp.zip")
    objs = objects_of(db, snap)
    partner = objs["S-1-5-21-9-9-9"]
    assert partner.kind == "Domain" and partner.name == "PARTNER.LOCAL"
    assert partner.properties == {"aegis_placeholder": True}
    assert result.summary["placeholders_created"] >= 1
    assert any("placeholder" in w for w in result.summary["warnings"])


def test_placeholder_is_upgraded_when_the_real_object_arrives_later(tmp_path, service, db):
    snap = service.create_snapshot("corp")
    groups = bh_file("groups", [group(1201, "HELPDESK", members=[(sid(1102), "User")])])
    service.import_file(snap, write_json(tmp_path / "groups.json", groups), "groups.json")
    assert objects_of(db, snap)[sid(1102)].properties == {"aegis_placeholder": True}

    users = bh_file("users", [user(1102, "BOB", description="helpdesk tech")])
    result = service.import_file(snap, write_json(tmp_path / "users.json", users), "users.json")
    bob = objects_of(db, snap)[sid(1102)]
    assert bob.name == "BOB@CORP.LOCAL" and bob.properties["description"] == "helpdesk tech"
    assert "aegis_placeholder" not in bob.properties
    assert result.summary["placeholders_resolved"] == 1


def test_duplicate_objects_across_files_are_merged(tmp_path, service, db):
    snap = service.create_snapshot("corp")
    a = bh_file("users", [user(1101, "ALICE", description="first")])
    b = bh_file("users", [user(1101, "ALICE", title_unused="x", admincount=True)])
    zpath = write_zip(tmp_path / "dup.zip", {"a_users.json": a, "b_users.json": b})
    result = service.import_file(snap, zpath, "dup.zip")
    alice = objects_of(db, snap)[sid(1101)]
    assert result.summary["objects_merged_duplicates"] == 1
    assert alice.properties["description"] == "first" and alice.properties["admincount"] is True


def test_duplicate_relationships_collapse(tmp_path, service, db):
    snap = service.create_snapshot("corp")
    g = group(1201, "HELPDESK", aces=[ace(sid(1101), "GenericAll"), ace(sid(1101), "GenericAll", inherited=True)])
    result = service.import_file(snap, write_json(tmp_path / "groups.json", bh_file("groups", [g])), "groups.json")
    assert [k for (_, k, _) in edges_of(db, snap)].count("GenericAll") == 1
    assert result.summary["relationships_duplicate_in_upload"] == 1


def test_reimporting_the_same_file_is_rejected(tmp_path, service):
    snap = service.create_snapshot("corp")
    path = sharphound_zip(tmp_path / "corp.zip")
    service.import_file(snap, path, "corp.zip")
    with pytest.raises(ConflictError, match="already been imported"):
        service.import_file(snap, path, "corp.zip")


def test_snapshot_stats_and_import_job_record(tmp_path, service, db):
    snap = service.create_snapshot("corp")
    result = service.import_file(snap, sharphound_zip(tmp_path / "corp.zip"), "corp.zip")
    with db.session() as s:
        snapshot = s.get(Snapshot, snap)
        job = s.get(ImportJob, result.import_job_id)
        assert snapshot.status == "ready"
        assert snapshot.stats["objects_by_kind"]["User"] == 3
        assert snapshot.stats["objects_by_kind"]["ServiceAccount"] == 1
        assert snapshot.stats["relationships_total"] == result.summary["relationships_inserted"]
        assert snapshot.collected_at is not None  # from the ZIP member timestamps
        assert snapshot.source_kind == "bloodhound"
        assert job.status == "succeeded" and len(job.sha256) == 64 and job.finished_at


def test_session_collection_failures_and_deleted_objects_are_counted(tmp_path, service):
    files = small_domain()
    files["users"]["data"].append({**user(1199, "GONE"), "IsDeleted": True})
    snap = service.create_snapshot("corp")
    result = service.import_file(snap, sharphound_zip(tmp_path / "corp.zip", files), "corp.zip")
    assert result.summary["deleted_objects_skipped"] == 1
    assert result.summary["session_collections_failed"] == 2  # RegistrySessions not collected on 2 computers


def test_bom_and_missing_meta_with_type_from_filename(tmp_path, service, db):
    content = {"data": [user(1101, "ALICE")]}  # no meta block
    path = write_json(tmp_path / "20261101_users.json", content, bom=True)
    snap = service.create_snapshot("corp")
    result = service.import_file(snap, path, "20261101_users.json")
    assert result.status == "succeeded"
    assert sid(1101) in objects_of(db, snap)
    assert any("inferred from the name" in w for w in result.summary["warnings"])


def test_legacy_v4_local_admins_format(tmp_path, service, db):
    legacy = {"ObjectIdentifier": sid(1301), "Properties": {"name": "SRV01.CORP.LOCAL"},
              "LocalAdmins": [{"MemberId": "x", "ObjectIdentifier": sid(1201), "ObjectType": "Group"}],
              "Sessions": [{"UserId": "", "UserSID": sid(1103), "ComputerSID": sid(1301)}], "Aces": []}
    snap = service.create_snapshot("legacy")
    service.import_file(snap, write_json(tmp_path / "computers.json", bh_file("computers", [legacy], version=4)),
                        "computers.json")
    e = edges_of(db, snap)
    assert (sid(1201), "AdminTo", sid(1301)) in e
    assert (sid(1301), "HasSession", sid(1103)) in e


def test_well_known_principal_ids_and_case_normalisation(tmp_path, service, db):
    g = group(f"{'corp.local'}-S-1-5-32-544", "ADMINISTRATORS", members=[(sid(512).lower(), "Group")])
    snap = service.create_snapshot("corp")
    service.import_file(snap, write_json(tmp_path / "groups.json", bh_file("groups", [g])), "groups.json")
    assert (sid(512).upper(), "MemberOf", "CORP.LOCAL-S-1-5-32-544") in edges_of(db, snap)
