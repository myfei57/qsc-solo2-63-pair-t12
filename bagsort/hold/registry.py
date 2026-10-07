"""The forensic hold registry: place, protect, re-check and release holds.

It is the single owner of the hold lifecycle and the mutation gate the store
consults on every staged command. Its guarantees:

* **Registered on disk** — a placed hold is a ``hold.put`` command folded into
  the same checksummed journal as everything else, with a sealed manifest, and
  is persisted to the on-disk snapshot immediately.
* **History is immutable while held** — neither destructive rewrites
  (``*.remove``, queue/collection clears, remaps) nor ``compact`` may disturb a
  pinned journal sequence, and ``reset`` is refused outright.
* **Release needs a basis and an authorised releaser** — separation of duties
  from the placing officer, the policy not-before date, a citation and a
  signed credential. Storage pressure is never a basis.
* **Item by item review** — the manifest enumerates every retained record with
  its content hash, and :meth:`HoldRegistry.verify_hold` re-proves each one.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from bagsort.audit.chain import AuditChain, digest_of
from bagsort.clock import Clock
from bagsort.errors import ConflictError, HoldViolation, NotFoundError, ValidationError
from bagsort.ids import IdFactory
from bagsort.model.entities import AuditEntry
from bagsort.store.journal import JournalEntry
from bagsort.store.replay import replay
from bagsort.store.store import Store
from .auth import ROLE_HOLDER, ROLE_RELEASER, Authorizer
from .manifest import (
    POLICY_EVENT,
    POLICY_INVESTIGATION,
    STATE_RELEASED,
    SUBJECT_SEQUENCE,
    HoldManifest,
    ScopeSpec,
    digest,
    freeze_scope,
)

# Destructive command kinds. Tuple values name the payload field carrying the
# affected subject; an empty tuple marks a command that clears a collection and
# is therefore vetted contextually against the live state. The ``*.put``
# rewrites are included because they overwrite the entity a hold retains; a
# retained record must remain byte-stable even though new history can append.
_DESTRUCTIVE: dict[str, tuple[str, ...]] = {
    "bag.put": ("bag.id",),
    "bag.remove": ("bag_id",),
    "flight.put": ("flight.id",),
    "flight.remove": ("flight_id",),
    "mapping.put": ("bag_id",),
    "recheck.dequeue": ("bag_id",),
    "recheck.clear": (),
    "transfer.clear_before": (),
    "belt.clear": (),
}


def _nested(payload: dict[str, Any], path: str) -> Any:
    """Read a dotted payload path such as ``bag.id``."""

    value: Any = payload
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _parse_utc(value: str) -> datetime:
    from datetime import timezone

    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValidationError(f"timestamp {value!r} is not UTC ISO-8601") from exc


class HoldRegistry:
    """Owns every hold and enforces them against the store."""

    def __init__(
        self, store: Store, clock: Clock, audit: AuditChain, authorizer: Authorizer
    ) -> None:
        self._store = store
        self._clock = clock
        self._audit = audit
        self._auth = authorizer
        self._ids = IdFactory("hold")
        store.install_guard(self)

    # -- reads -------------------------------------------------------------

    def list(self, active_only: bool = False) -> list[HoldManifest]:
        holds = self._store.state().holds.values()
        return sorted(
            (hold for hold in holds if not active_only or hold.active),
            key=lambda hold: hold.placed_at,
        )

    def get(self, hold_id: str) -> HoldManifest:
        hold = self._store.state().holds.get(hold_id)
        if hold is None:
            raise NotFoundError(f"no hold {hold_id!r}")
        return hold

    def record(self, sequence: int) -> JournalEntry:
        for entry in self._store.entries():
            if entry.sequence == sequence:
                return entry
        raise NotFoundError(f"journal sequence {sequence} is no longer present")

    def pinned_sequences(self) -> set[int]:
        """Every journal sequence any active hold currently pins."""

        pinned: set[int] = set()
        for hold in self.list(active_only=True):
            pinned.update(hold.sequences)
        return pinned

    def storage_review(self) -> dict[str, Any]:
        """Cost and retention figures, so retained storage can be re-checked."""

        entries = self._store.entries()
        sizes = [len(entry.kind) + len(str(entry.payload)) for entry in entries]
        pinned = self.pinned_sequences()
        total = sum(sizes)
        held_bytes = sum(
            size for entry, size in zip(entries, sizes) if entry.sequence in pinned
        )
        per_hold: dict[str, int] = {}
        for hold in self.list(active_only=True):
            wanted = set(hold.sequences)
            per_hold[hold.id] = sum(
                size for entry, size in zip(entries, sizes) if entry.sequence in wanted
            )
        return {
            "journal_entries": len(entries),
            "journal_bytes": total,
            "pinned_entries": len(pinned),
            "pinned_bytes": held_bytes,
            "reclaimable_bytes": total - held_bytes,
            "active_holds": len(per_hold),
            "by_hold": [
                {
                    "id": hold.id,
                    "matter": hold.matter,
                    "anchor": hold.anchor,
                    "items": len(hold.items),
                    "bytes": per_hold[hold.id],
                    "not_before": hold.not_before,
                }
                for hold in self.list(active_only=True)
            ],
        }

    # -- place / extend / release -----------------------------------------

    def place(
        self,
        matter: str,
        scopes: list[dict[str, Any]],
        credential: str,
        rationale: str = "",
        anchor: str = POLICY_EVENT,
        event_at: str = "",
        retention_days: int = 90,
    ) -> HoldManifest:
        """Freeze the enumerated scope immediately and register it durably."""

        principal = self._auth.authenticate(credential)
        principal.require(ROLE_HOLDER)
        if not matter.strip():
            raise ValidationError("a hold needs a matter reference")
        if anchor not in (POLICY_EVENT, POLICY_INVESTIGATION):
            raise ValidationError(f"unknown hold anchor {anchor!r}")
        if anchor == POLICY_EVENT and retention_days <= 0:
            raise ValidationError("an event-time hold needs a positive retention window")

        specs = self._validate_scopes(scopes)
        items = freeze_scope(specs, self._store.entries())
        now = self._clock.now_iso()
        event_time = event_at or now
        if anchor == POLICY_EVENT and _parse_utc(event_time) > self._clock.now():
            raise ValidationError("the incident event time cannot lie in the future")
        not_before = self._not_before(anchor, event_time, retention_days)
        hold_id = self._ids.next()

        manifest = HoldManifest(
            id=hold_id,
            matter=matter.strip(),
            scope=tuple(specs),
            items=items,
            anchor=anchor,
            placed_at=now,
            event_at=event_time,
            retention_days=retention_days,
            not_before=not_before,
            placed_by=principal.name,
            rationale=rationale.strip(),
        ).sealed()

        audit_entry = self._compose_audit(
            "hold.placed",
            hold_id,
            {
                "matter": manifest.matter,
                "anchor": anchor,
                "items": len(items),
                "seal": manifest.seal,
                "not_before": not_before,
            },
        )
        with self._store.session() as session:
            session.state.holds[hold_id] = manifest
            session.state.audit.append(audit_entry)
            session.record("hold.put", {"hold": manifest.as_dict()}, now)
            session.record("audit.append", {"entry": audit_entry.as_dict()}, now)
        self._persist()
        return self.get(hold_id)

    def extend(self, hold_id: str, days: int, credential: str, basis: str) -> HoldManifest:
        """Lengthen an event-time hold before it becomes releasable."""

        principal = self._auth.authenticate(credential)
        principal.require(ROLE_HOLDER)
        hold = self.get(hold_id)
        self._require_active(hold)
        if hold.anchor != POLICY_EVENT:
            raise ConflictError("a matter-close hold has no fixed window to extend")
        if days <= 0:
            raise ValidationError("extension days must be positive")
        if not basis.strip():
            raise ValidationError("an extension must cite its basis")
        now = self._clock.now_iso()
        extended_days = hold.extension_days + days
        not_before = self._not_before(
            hold.anchor, hold.event_at, hold.retention_days + extended_days
        )
        updated = HoldManifest.from_dict(
            {
                **hold.as_dict(),
                "extension_days": extended_days,
                "not_before": not_before,
                "extended_at": now,
                "extended_by": principal.name,
                "seal": "",
            }
        ).sealed()
        self._commit_update(
            updated,
            "hold.extended",
            {"extension_days": extended_days, "basis": basis.strip(), "not_before": not_before},
        )
        return self.get(hold_id)

    def release(
        self,
        hold_id: str,
        credential: str,
        basis: str,
        authorization: str,
    ) -> HoldManifest:
        """Release a hold; only with a cited basis, on schedule, by a releaser."""

        principal = self._auth.authenticate(credential)
        principal.require(ROLE_RELEASER)
        hold = self.get(hold_id)
        self._require_active(hold)
        if principal.name == hold.placed_by:
            raise ConflictError("the placing officer may not also release the hold")
        if not basis.strip():
            raise ValidationError("release must state the dispositive basis")
        if not authorization.strip():
            raise ValidationError("release must cite the authorising instrument")
        if hold.anchor == POLICY_EVENT and self._clock.now() < _parse_utc(hold.not_before):
            raise ConflictError(
                f"hold {hold_id!r} cannot release before {hold.not_before}; "
                "storage pressure is not a basis"
            )
        # A matter_close hold carries no not_before: it stays until an explicit,
        # authorised release cites the investigation closure.
        now = self._clock.now_iso()
        updated = HoldManifest.from_dict(
            {
                **hold.as_dict(),
                "status": STATE_RELEASED,
                "released_at": now,
                "released_by": principal.name,
                "release_basis": basis.strip(),
                "release_authorization": authorization.strip(),
                "seal": "",
            }
        ).sealed()
        self._commit_update(
            updated,
            "hold.released",
            {"basis": basis.strip(), "authorization": authorization.strip()},
        )
        return self.get(hold_id)

    # -- verification ------------------------------------------------------

    def verify_hold(self, hold_id: str) -> dict[str, Any]:
        """Re-prove a manifest seal and every one of its retained records."""

        hold = self.get(hold_id)
        entries = {entry.sequence: entry for entry in self._store.entries()}
        items: list[dict[str, Any]] = []
        for item in hold.items:
            entry = entries.get(item.sequence)
            current = digest([entry.kind, entry.payload]) if entry is not None else ""
            items.append(
                {
                    "sequence": item.sequence,
                    "kind": item.kind,
                    "subject": item.subject,
                    "present": entry is not None,
                    "unchanged": current == item.content_hash,
                }
            )
        missing = [item["sequence"] for item in items if not item["present"]]
        altered = [
            item["sequence"] for item in items if item["present"] and not item["unchanged"]
        ]
        intact = (
            hold.verify_seal()
            and not missing
            and not altered
            and self._audit.verify()
        )
        return {
            "hold": hold.id,
            "status": hold.status,
            "seal_intact": hold.verify_seal(),
            "audit_intact": self._audit.verify(),
            "items_expected": len(hold.items),
            "items_present": len(hold.items) - len(missing),
            "missing_sequences": missing,
            "altered_sequences": altered,
            "items": items,
            "intact": intact,
        }

    # -- compaction --------------------------------------------------------

    def compact(self, credential: str) -> dict[str, Any]:
        """Reclaim history that no active hold retains.

        Every pinned record, hold registration and audit entry survives
        verbatim with its original sequence number. The removed records are
        folded into a ``state.snapshot`` checkpoint placed at the truncation
        watermark, so replaying the smaller journal rebuilds exactly the same
        materialised state. The compaction itself is appended as an audit entry
        and re-verified before the compacted log is accepted.
        """

        principal = self._auth.authenticate(credential)
        principal.require(ROLE_RELEASER)
        committed = self._store.entries()
        pinned = self.pinned_sequences()
        eternal = {"hold.put", "audit.append"}
        must_keep = {
            entry.sequence
            for entry in committed
            if entry.sequence in pinned or entry.kind in eternal
        }
        removed = sorted(
            entry.sequence for entry in committed if entry.sequence not in must_keep
        )
        if not removed:
            return {"removed": 0, "removed_sequences": [], "watermark": self._store.watermark}

        state_before = self._store.state()
        floor = max(removed)
        surviving = [
            entry
            for entry in committed
            if entry.sequence in must_keep and entry.sequence < floor
        ]
        later = [entry for entry in committed if entry.sequence > floor]
        snapshot = JournalEntry(
            sequence=floor,
            kind="state.snapshot",
            payload={
                "watermark": floor,
                "folded_sequences": [entry.sequence for entry in surviving],
                "state": state_before.as_dict(),
            },
            at=self._clock.now_iso(),
        )
        audit_entry = self._compose_audit(
            "hold.compacted",
            f"compact:{floor}",
            {"removed": len(removed), "pinned": len(pinned), "floor": floor},
        )
        compaction_audit = JournalEntry(
            sequence=self._store.watermark + 1,
            kind="audit.append",
            payload={"entry": audit_entry.as_dict()},
            at=audit_entry.at,
        )
        candidate = surviving + [snapshot] + later + [compaction_audit]

        rebuilt = replay(candidate)
        if rebuilt.as_dict() != self._expected_after(state_before, audit_entry):
            raise HoldViolation("compaction would change the materialised state; refusing")
        if not _audit_links(rebuilt.audit, audit_entry):
            raise HoldViolation("compaction broke the audit chain; refusing")

        self._store.adopt_entries(candidate)
        self._persist()
        return {
            "removed": len(removed),
            "removed_sequences": removed,
            "pinned_kept": len(pinned),
            "watermark": self._store.watermark,
            "by": principal.name,
        }

    def _expected_after(self, state_before, audit_entry: AuditEntry) -> dict[str, Any]:
        expected = state_before.as_dict()
        audit = [entry for entry in expected["audit"]]
        audit.append(audit_entry.as_dict())
        expected["audit"] = audit
        return expected

    # -- store guard -------------------------------------------------------

    def vet(self, kind: str, payload: dict[str, Any]) -> None:
        """Reject a staged command that would disturb a retained record."""

        fields = _DESTRUCTIVE.get(kind)
        if fields is None:
            return
        pinned_subjects = self._pinned_subjects()
        subjects = {
            str(value)
            for name in fields
            if (value := _nested(payload, name))
        }
        if fields:
            hit = subjects & pinned_subjects
            if hit:
                raise HoldViolation(
                    f"{kind} targets a retained record for subject(s) {sorted(hit)}"
                )
            return
        if self._collection_touches_hold(kind, payload, pinned_subjects):
            raise HoldViolation(
                f"{kind} would clear a record retained by an active hold"
            )

    def vet_reset(self) -> None:
        active = self.list(active_only=True)
        if active:
            raise HoldViolation(
                f"reset refused: {len(active)} active hold(s) retain records"
            )

    def _collection_touches_hold(
        self, kind: str, payload: dict[str, Any], pinned_subjects: set[str]
    ) -> bool:
        state = self._store.state()
        if kind == "recheck.clear":
            return bool(pinned_subjects.intersection(state.recheck_queue))
        if kind == "belt.clear":
            return bool(pinned_subjects.intersection(state.belt_on_carousel))
        if kind == "transfer.clear_before":
            floor = int(payload.get("batch", 0))
            doomed = {
                command.id for command in state.transfer_commands if command.batch < floor
            }
            return bool(doomed & pinned_subjects)
        return False

    # -- internals ---------------------------------------------------------

    def _validate_scopes(self, raw_scopes: list[dict[str, Any]]) -> list[ScopeSpec]:
        if not raw_scopes:
            raise ValidationError("a hold needs at least one scope selector")
        return [ScopeSpec.from_dict(raw) for raw in raw_scopes]

    def _not_before(self, anchor: str, event_at: str, retention_days: int) -> str:
        if anchor == POLICY_INVESTIGATION:
            return ""
        moment = _parse_utc(event_at) + timedelta(days=retention_days)
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _require_active(self, hold: HoldManifest) -> None:
        if not hold.active:
            raise ConflictError(f"hold {hold.id!r} was already released")

    def _pinned_subjects(self) -> set[str]:
        """Subject ids protected from future destructive rewrites."""

        subjects: set[str] = set()
        for hold in self.list(active_only=True):
            for spec in hold.scope:
                if spec.kind != SUBJECT_SEQUENCE:
                    subjects.update(spec.ids)
            subjects.update(item.subject for item in hold.items if item.subject)
        return subjects

    def _compose_audit(self, kind: str, subject: str, detail: dict[str, Any]) -> AuditEntry:
        previous = self._audit.last_digest()
        sequence = self._audit.count() + 1
        entry = AuditEntry(
            sequence=sequence,
            kind=kind,
            subject=subject,
            detail={"stage": "hold", "stage_index": self._audit_stage_index(), **detail},
            prev_digest=previous,
            at=self._clock.now_iso(),
        )
        return AuditEntry(**{**entry.as_dict(), "digest": digest_of(entry)})

    def _audit_stage_index(self) -> int:
        index = self._audit.topology_index("hold")
        return index if index >= 0 else 99

    def _commit_update(
        self, updated: HoldManifest, audit_kind: str, detail: dict[str, Any]
    ) -> None:
        now = self._clock.now_iso()
        audit_entry = self._compose_audit(audit_kind, updated.id, detail)
        with self._store.session() as session:
            session.state.holds[updated.id] = updated
            session.state.audit.append(audit_entry)
            session.record("hold.put", {"hold": updated.as_dict()}, now)
            session.record("audit.append", {"entry": audit_entry.as_dict()}, now)
        self._persist()

    def _persist(self) -> None:
        # A hold registration must land on disk immediately, never waiting on a
        # later operator to persist the process.
        self._store.persist()


def _audit_links(entries: list[AuditEntry], tail: AuditEntry) -> bool:
    """The rebuilt audit chain must still hash-link, ending on the compaction."""

    if not entries or entries[-1].digest != tail.digest:
        return False
    previous = entries[0].prev_digest
    for entry in entries:
        if entry.prev_digest != previous or digest_of(entry) != entry.digest:
            return False
        previous = entry.digest
    return True
