# AEGIS — Supported Import Formats

AEGIS imports data that has **already been collected**. It never runs collectors or connects to a directory.
Uploads can be `.zip`, `.json` or `.csv`. The extension must match the content.

## 1. SharpHound / BloodHound CE JSON (format versions 4, 5 and 6)

Upload the SharpHound `.zip` as produced, or individual `*_users.json`, `*_groups.json`, ... files.
The file type comes from `meta.type`. If `meta` is missing, it is inferred from the file name and a warning is shown.

Supported types: users, groups, computers, domains, ous, gpos, containers, certtemplates, enterprisecas, rootcas,
aiacas, ntauthstores, issuancepolicies. Certificate-services objects are stored as nodes with their ACLs; ADCS
escalation rules are planned for later.

| SharpHound field | AEGIS relationship (source → destination) |
|---|---|
| `Aces[]` | principal → object, kind = `RightName` (GenericAll, WriteDacl, ...) |
| `Members[]` | member → group, `MemberOf` |
| `PrimaryGroupSID` | object → group, `MemberOf` (flagged as primary group) |
| `Sessions`, `PrivilegedSessions`, `RegistrySessions` | computer → user, `HasSession` (confidence 0.7 / 0.8 / 0.6) |
| `LocalGroups[]` RID 544 / 555 / 562 / 580 | member → computer, `AdminTo` / `CanRDP` / `ExecuteDCOM` / `CanPSRemote` |
| Legacy `LocalAdmins`, `RemoteDesktopUsers`, `DcomUsers`, `PSRemoteUsers` | same as above |
| `UserRights[]` SeRemoteInteractiveLogonRight | member → computer, `CanRDP` |
| `AllowedToDelegate[]` | object → computer, `AllowedToDelegate` |
| `AllowedToAct[]` | principal → computer, `AllowedToAct` (RBCD) |
| `HasSIDHistory[]` | object → principal, `HasSIDHistory` |
| `SPNTargets[]` with service SQLAdmin | user → computer, `SQLAdmin` |
| `ChildObjects[]` / `ContainedBy` | container → child, `Contains` |
| `Links[]` | GPO → OU/domain, `GPLink` (records whether it is enforced) |
| `Trusts[]` | trusted domain → trusting domain, `TrustedBy` |

Objects with `IsDeleted: true` are skipped. Users with SPNs, gMSAs and MSAs become `ServiceAccount` (`base_kind: User`).
Ingestion records only *observations*. Whether a relationship can be traversed in an attack path is decided by the
graph engine's rules.

## 2. AEGIS JSON inventory

```json
{
  "format": "aegis-inventory",
  "version": 1,
  "collected_at": "2026-11-01T10:00:00Z",
  "objects": [
    {"id": "S-1-5-21-1-2-3-1105", "kind": "User", "name": "SVC_SQL@CORP.LOCAL",
     "domain": "CORP.LOCAL", "enabled": true, "properties": {"hasspn": true}}
  ],
  "relationships": [
    {"source": "S-1-5-21-1-2-3-1105", "target": "S-1-5-21-1-2-3-1201", "kind": "AdminTo",
     "confidence": 0.9, "evidence": "Local admin per CMDB export", "inherited": false}
  ]
}
```
* `kind` (objects): User, Group, Computer, Domain, OU, GPO, Container, ServiceAccount, CertTemplate, EnterpriseCA, RootCA,
  AIACA, NTAuthStore, IssuancePolicy, LocalUser, LocalGroup. Aliases such as `organizationalunit` are accepted.
* Relationship `kind`: letters, digits and underscore, starting with a letter (e.g. `GenericAll`).
* Unknown fields are rejected per record, and the rest of the file still imports.

## 3. CSV inventories (UTF-8, header row required)

* **Objects:** `id,kind,name[,domain,enabled,<any extra columns become properties>]`
* **Relationships:** `source,target,kind[,confidence,evidence,collected_at,inherited,data_source]`

Both can be uploaded together in one ZIP, in any order.

## Rules that apply to every format
* Identifiers (SIDs, GUIDs, custom IDs) are upper-cased. They must match `[A-Za-z0-9{][A-Za-z0-9._@{}:-]*` and be at most 128 characters.
* Text has control characters and invisible or bidirectional-override characters removed, and is length-capped.
* An object that appears more than once is merged. A relationship that appears more than once is stored once.
* An object referenced but not supplied becomes a **placeholder** (shown as a collection gap). It is replaced
  automatically if a later upload provides it.
* An import is atomic. Unsafe archives, limit breaches and cancellations roll everything back. Problems in individual
  records or files are reported with their location, and the import is marked `partial`.
* Uploading exactly the same file into the same snapshot twice is rejected.
