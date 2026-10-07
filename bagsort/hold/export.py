"""Forensic export bundle.

An export is not just rows: it is a self describing bundle a third party can
verify offline without trusting the running system. Every retained journal
entry is included verbatim with the digest the envelope would compute, each
manifest carries its seal, and the bundle digest binds them together with the
audit head. :func:`verify_bundle` therefore checks the same facts the chain and
the command log assert, so the audit chain, the command log and the export
"咬合" (bite together): tampering with any one breaks the bundle digest.
"""

from __future__ import annotations

from typing import Any, Iterable

from bagsort.audit.chain import GENESIS, digest_of
from bagsort.hold.manifest import HoldManifest, digest
from bagsort.model.entities import AuditEntry
from bagsort.store.journal import JournalEntry
from bagsort.store.snapshot import digest_for


def entry_digest(entry: JournalEntry) -> str:
    return digest([entry.kind, entry.payload])


def build_bundle(holds: Iterable[HoldManifest], entries: list[JournalEntry]) -> dict[str, Any]:
    """Assemble an independently verifiable export of the given holds."""

    selected_holds = list(holds)
    wanted = {sequence for hold in selected_holds for sequence in hold.sequences}
    records = [entry for entry in entries if entry.sequence in wanted]
    audit_tail = _audit_head(entries)
    manifests = [hold.as_dict() for hold in selected_holds]
    records_out = [
        {
            "sequence": entry.sequence,
            "kind": entry.kind,
            "at": entry.at,
            "payload": entry.payload,
            "entry_hash": entry_digest(entry),
        }
        for entry in records
    ]
    envelope = {
        "manifest_count": len(manifests),
        "record_count": len(records_out),
        "journal_head_digest": digest_for(entries),
        "audit_head_digest": audit_tail,
        "manifests": manifests,
        "records": records_out,
    }
    return {"bundle": envelope, "digest": digest(_binding(envelope))}


def verify_bundle(bundle: dict[str, Any], audit_entries: list[AuditEntry] | None = None) -> dict[str, Any]:
    """Re-check every link in an exported bundle; returns a full report."""

    envelope = bundle.get("bundle", {})
    binding_ok = digest(_binding(envelope)) == bundle.get("digest")
    seal_results = [
        HoldManifest.from_dict(manifest).verify_seal() for manifest in envelope.get("manifests", [])
    ]
    record_results: list[dict[str, Any]] = []
    by_hold: dict[int, list[str]] = {}
    for manifest in envelope.get("manifests", []):
        for item in manifest.get("items", []):
            by_hold.setdefault(int(item["sequence"]), []).append(item["content_hash"])
    for record in envelope.get("records", []):
        sequence = int(record["sequence"])
        live_hash = digest([record["kind"], record["payload"]])
        expected = by_hold.get(sequence, [])
        record_results.append(
            {
                "sequence": sequence,
                "entry_hash_ok": live_hash == record["entry_hash"],
                "seal_cover_ok": bool(expected) and record["entry_hash"] in expected,
            }
        )
    audit_ok = True
    if audit_entries is not None:
        head = audit_entries[-1].digest if audit_entries else GENESIS
        audit_ok = head == envelope.get("audit_head_digest") and _audit_chain_ok(audit_entries)
    records_ok = all(
        result["entry_hash_ok"] and result["seal_cover_ok"] for result in record_results
    )
    return {
        "binding_intact": binding_ok,
        "seals_intact": all(seal_results) and bool(seal_results) == bool(envelope.get("manifests")),
        "records_intact": records_ok
        and len(record_results) == envelope.get("record_count", -1),
        "audit_intact": audit_ok,
        "record_checks": record_results,
        "intact": binding_ok and all(seal_results) and records_ok and audit_ok,
    }


def _audit_head(entries: list[JournalEntry]) -> str:
    audit_entries = [
        AuditEntry.from_dict(entry.payload["entry"])
        for entry in entries
        if entry.kind == "audit.append"
    ]
    return audit_entries[-1].digest if audit_entries else GENESIS


def _audit_chain_ok(entries: list[AuditEntry]) -> bool:
    previous = GENESIS
    for entry in entries:
        if entry.prev_digest != previous or digest_of(entry) != entry.digest:
            return False
        previous = entry.digest
    return True


def _binding(envelope: dict[str, Any]) -> list[Any]:
    return [
        envelope.get("manifest_count"),
        envelope.get("record_count"),
        envelope.get("journal_head_digest"),
        envelope.get("audit_head_digest"),
        [manifest.get("id") for manifest in envelope.get("manifests", [])],
        [record["sequence"] for record in envelope.get("records", [])],
    ]
