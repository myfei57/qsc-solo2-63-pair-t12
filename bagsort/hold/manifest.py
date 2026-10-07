"""The sealed manifest describing exactly what one hold retains.

A request to retain records arrives as a loose scope (bag ids, flight ids, audit
subjects or explicit journal sequences). At *place* time that scope is resolved
against the committed journal into an enumerated, item by item list, and frozen
into a manifest whose digest covers the scope, the anchor and every retained
sequence. From that moment the scope cannot drift: later reorganisation cannot
silently widen or narrow it, and every retained record can be re-checked
individually against ``items``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from bagsort.errors import ValidationError

if TYPE_CHECKING:  # the journal is needed for annotations only
    from bagsort.store.journal import JournalEntry

# Anchors ---------------------------------------------------------------------

POLICY_EVENT = "event_time"
POLICY_INVESTIGATION = "matter_close"
POLICIES = (POLICY_EVENT, POLICY_INVESTIGATION)

# Statuses --------------------------------------------------------------------

STATE_ACTIVE = "active"
STATE_RELEASED = "released"

# Subject kinds ---------------------------------------------------------------

SUBJECT_BAG = "bag"
SUBJECT_FLIGHT = "flight"
SUBJECT_AUDIT = "audit"
SUBJECT_TRANSFER = "transfer"
SUBJECT_SEQUENCE = "sequence"
SUBJECT_KINDS = (
    SUBJECT_BAG,
    SUBJECT_FLIGHT,
    SUBJECT_AUDIT,
    SUBJECT_TRANSFER,
    SUBJECT_SEQUENCE,
)


def canonical(value: Any) -> str:
    """Deterministic JSON used for every hold digest."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ScopeSpec:
    """One selector in a hold request before it is enumerated."""

    kind: str
    ids: tuple[str, ...] = ()
    sequences: tuple[int, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ScopeSpec":
        kind = str(raw.get("kind", ""))
        if kind not in SUBJECT_KINDS:
            raise ValidationError(f"unknown hold scope kind {kind!r}")
        ids = tuple(str(item) for item in raw.get("ids", ()) if str(item))
        sequences = tuple(sorted(int(item) for item in raw.get("sequences", ()) if int(item) > 0))
        if kind == SUBJECT_SEQUENCE:
            if not sequences:
                raise ValidationError("a sequence scope needs at least one journal sequence")
        elif not ids:
            raise ValidationError(f"a {kind!r} scope needs at least one id")
        return cls(kind=kind, ids=ids, sequences=sequences)

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "ids": list(self.ids), "sequences": list(self.sequences)}


@dataclass(frozen=True)
class HeldItem:
    """One enumerated journal record pinned by a hold."""

    sequence: int
    kind: str
    subject: str
    content_hash: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "subject": self.subject,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "HeldItem":
        return cls(
            sequence=int(raw["sequence"]),
            kind=str(raw.get("kind", "")),
            subject=str(raw.get("subject", "")),
            content_hash=str(raw.get("content_hash", "")),
        )


def entry_subject(entry: JournalEntry) -> str:
    """Extract the entity a journal command acts on, for scope matching."""

    payload = entry.payload
    kind = entry.kind
    if kind in {"bag.put", "bag.remove"}:
        return str(payload.get("bag", {}).get("id") or payload.get("bag_id", ""))
    if kind in {"flight.put", "flight.remove"}:
        return str(payload.get("flight", {}).get("id") or payload.get("flight_id", ""))
    if kind == "audit.append":
        return str(payload.get("entry", {}).get("subject", ""))
    if kind == "transfer.append":
        return str(payload.get("command", {}).get("id", ""))
    if kind == "transfer.clear_before":
        return ""
    for name in ("bag_id", "flight_id"):
        if name in payload:
            return str(payload[name])
    record = payload.get("record")
    if isinstance(record, dict) and record.get("bag_id"):
        return str(record["bag_id"])
    command = payload.get("command")
    if isinstance(command, dict) and command.get("id"):
        return str(command["id"])
    return ""


def _entry_kind(entry: JournalEntry) -> str:
    if entry.kind == "audit.append":
        return SUBJECT_AUDIT
    if entry.kind in {"transfer.append", "transfer.clear_before"}:
        return SUBJECT_TRANSFER
    if entry.kind.startswith("bag."):
        return SUBJECT_BAG
    if entry.kind.startswith("flight."):
        return SUBJECT_FLIGHT
    return ""


def freeze_scope(
    specs: list[ScopeSpec], entries: list[JournalEntry]
) -> tuple[HeldItem, ...]:
    """Enumerate the retained journal records, rejecting any unresolved scope.

    Every requested id or explicit sequence must match at least one committed
    record. Returning a partial manifest would let a typo quietly retain
    nothing, so the whole place request fails instead.
    """

    selected: dict[int, HeldItem] = {}
    unmatched: list[str] = []

    def pinned(number: int, entry: JournalEntry) -> HeldItem:
        return HeldItem(
            sequence=number,
            kind=entry.kind,
            subject=entry_subject(entry),
            content_hash=digest([entry.kind, entry.payload]),
        )

    for spec in specs:
        matched: dict[int, HeldItem] = {}
        if spec.kind == SUBJECT_SEQUENCE:
            by_sequence = {entry.sequence: entry for entry in entries}
            for number in spec.sequences:
                entry = by_sequence.get(number)
                if entry is None:
                    unmatched.append(f"#{number}")
                else:
                    matched[number] = pinned(number, entry)
        else:
            wanted = set(spec.ids)
            for entry in entries:
                if _entry_kind(entry) != spec.kind:
                    continue
                subject = entry_subject(entry)
                if subject in wanted:
                    matched[entry.sequence] = pinned(entry.sequence, entry)
            found = {item.subject for item in matched.values()}
            unmatched.extend(f"{spec.kind}:{missing}" for missing in sorted(wanted - found))
        selected.update(matched)
    if unmatched:
        raise ValidationError("hold scope matched no committed record: " + ", ".join(unmatched))
    return tuple(selected[number] for number in sorted(selected))


@dataclass(frozen=True)
class HoldManifest:
    """The sealed registration of one forensic hold."""

    id: str
    matter: str
    scope: tuple[ScopeSpec, ...]
    items: tuple[HeldItem, ...]
    anchor: str
    placed_at: str
    event_at: str
    retention_days: int
    not_before: str
    placed_by: str
    rationale: str = ""
    status: str = STATE_ACTIVE
    seal: str = ""
    extension_days: int = 0
    extended_at: str = ""
    extended_by: str = ""
    released_at: str = ""
    released_by: str = ""
    release_basis: str = ""
    release_authorization: str = ""

    @property
    def sequences(self) -> tuple[int, ...]:
        return tuple(item.sequence for item in self.items)

    @property
    def active(self) -> bool:
        return self.status == STATE_ACTIVE

    def unsealed_material(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "matter": self.matter,
            "scope": [spec.as_dict() for spec in self.scope],
            "items": [item.as_dict() for item in self.items],
            "anchor": self.anchor,
            "placed_at": self.placed_at,
            "event_at": self.event_at,
            "retention_days": self.retention_days,
            "not_before": self.not_before,
            "placed_by": self.placed_by,
            "rationale": self.rationale,
        }

    def sealed(self) -> "HoldManifest":
        return replace(self, seal=digest(self.unsealed_material()))

    def verify_seal(self) -> bool:
        return self.seal == digest(self.unsealed_material())

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "matter": self.matter,
            "scope": [spec.as_dict() for spec in self.scope],
            "items": [item.as_dict() for item in self.items],
            "anchor": self.anchor,
            "placed_at": self.placed_at,
            "event_at": self.event_at,
            "retention_days": self.retention_days,
            "not_before": self.not_before,
            "placed_by": self.placed_by,
            "rationale": self.rationale,
            "status": self.status,
            "seal": self.seal,
            "extension_days": self.extension_days,
            "extended_at": self.extended_at,
            "extended_by": self.extended_by,
            "released_at": self.released_at,
            "released_by": self.released_by,
            "release_basis": self.release_basis,
            "release_authorization": self.release_authorization,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "HoldManifest":
        anchor = str(raw.get("anchor", POLICY_EVENT))
        if anchor not in POLICIES:
            raise ValidationError(f"unknown hold anchor {anchor!r}")
        return cls(
            id=str(raw["id"]),
            matter=str(raw.get("matter", "")),
            scope=tuple(ScopeSpec.from_dict(item) for item in raw.get("scope", [])),
            items=tuple(HeldItem.from_dict(item) for item in raw.get("items", [])),
            anchor=anchor,
            placed_at=str(raw.get("placed_at", "")),
            event_at=str(raw.get("event_at", "")),
            retention_days=int(raw.get("retention_days", 0)),
            not_before=str(raw.get("not_before", "")),
            placed_by=str(raw.get("placed_by", "")),
            rationale=str(raw.get("rationale", "")),
            status=str(raw.get("status", STATE_ACTIVE)),
            seal=str(raw.get("seal", "")),
            extension_days=int(raw.get("extension_days", 0)),
            extended_at=str(raw.get("extended_at", "")),
            extended_by=str(raw.get("extended_by", "")),
            released_at=str(raw.get("released_at", "")),
            released_by=str(raw.get("released_by", "")),
            release_basis=str(raw.get("release_basis", "")),
            release_authorization=str(raw.get("release_authorization", "")),
        )
