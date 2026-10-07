"""Forensic holds: a registered, persisted freeze on a batch of records.

A hold pins every journal entry that mentions its subject at placement time.
The scope is registered entry by entry — sequence, kind and a digest of the
entry as placed — and is itself a committed journal command, so the
registration lands on disk with everything else and replays after a restart.
While a hold is active, grooming and compaction must not touch the pinned
entries, and the store refuses to wipe the journal.

**Retention anchoring.** The retention window is anchored at the event moment:
``until = event_at + retention`` is fixed when the hold is placed and never
moves. The alternative — holding until the investigation formally closes —
was rejected. The two policies trade the same two currencies in opposite
directions:

* Event-anchored (chosen): storage cost is bounded and predictable. The cost
  source is the pinned journal segment that compaction and grooming may not
  reclaim during the window; its size is event rate times window length, and
  it is paid as delayed reclamation, never as degraded write or read
  performance (the pin check is a single set lookup per entry). The price is
  evidence completeness: once the window closes and an authorised release
  lands, the records become reclaimable whether or not anyone has finished
  looking at them.
* Investigation-anchored (rejected): evidence survives exactly as long as the
  dispute lives, but the storage cost is unbounded — a forgotten investigation
  pins history forever, and reclamation depends on a human closing a case
  rather than on a clock the system can verify.

Release still requires the registering authority and an explicit basis, and
only once the window has expired. There is deliberately no early-release path:
storage pressure is the documented, bounded cost of the window, not a reason
to shorten it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from bagsort.clock import Clock
from bagsort.errors import ConflictError, NotFoundError, ValidationError
from bagsort.ids import IdFactory
from bagsort.model.entities import Hold, ScopeEntry
from bagsort.store.journal import JournalEntry
from bagsort.store.store import Store

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _parse_iso(value: str) -> datetime:
    try:
        return datetime.strptime(value, ISO_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValidationError(f"timestamp {value!r} is not ISO UTC") from exc


def _format_iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(ISO_FORMAT)


def _entry_digest(entry: JournalEntry) -> str:
    """Digest of one committed entry, registered so alteration is detectable."""

    material = json.dumps(
        entry.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _mentions(value: Any, subject: str) -> bool:
    if isinstance(value, str):
        return value == subject
    if isinstance(value, dict):
        return any(_mentions(item, subject) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_mentions(item, subject) for item in value)
    return False


class HoldBook:
    """Places, reviews and releases forensic holds over journal records."""

    def __init__(self, store: Store, clock: Clock, ids: IdFactory) -> None:
        self._store = store
        self._clock = clock
        self._ids = ids

    def place(
        self,
        subject: str,
        reason: str,
        authority: str,
        retention_seconds: int,
        event_at: str = "",
    ) -> Hold:
        """Register a hold over every committed entry that mentions ``subject``."""

        subject = subject.strip()
        reason = reason.strip()
        authority = authority.strip()
        if not subject:
            raise ValidationError("hold subject must not be empty")
        if not reason:
            raise ValidationError("hold reason must not be empty")
        if not authority:
            raise ValidationError("hold authority must not be empty")
        if retention_seconds <= 0:
            raise ValidationError("retention must be a positive number of seconds")
        for hold in self._store.state().holds.values():
            if hold.active and hold.subject == subject:
                raise ConflictError(
                    f"subject {subject!r} is already under forensic hold {hold.id}"
                )
        anchored = _parse_iso(event_at) if event_at.strip() else self._clock.now()
        until = anchored + timedelta(seconds=retention_seconds)
        scope = tuple(
            ScopeEntry(sequence=entry.sequence, kind=entry.kind, digest=_entry_digest(entry))
            for entry in self._store.entries()
            if _mentions(entry.payload, subject)
        )
        hold = Hold(
            id=self._ids.next(),
            subject=subject,
            reason=reason,
            authority=authority,
            event_at=_format_iso(anchored),
            until=_format_iso(until),
            placed_at=self._clock.now_iso(),
            scope=scope,
        )
        with self._store.session() as session:
            session.state.holds[hold.id] = hold
            session.record("hold.place", {"hold": hold.as_dict()}, hold.placed_at)
        return hold

    def release(self, hold_id: str, authority: str, basis: str) -> Hold:
        """Release an expired hold; only the registering authority may do so."""

        hold = self.get(hold_id)
        authority = authority.strip()
        basis = basis.strip()
        if not hold.active:
            raise ConflictError(f"hold {hold_id} is already released")
        if authority != hold.authority:
            raise ConflictError(
                f"hold {hold_id} may only be released by {hold.authority!r}"
            )
        if not basis:
            raise ValidationError("release basis must not be empty")
        if self._clock.now() < _parse_iso(hold.until):
            raise ConflictError(f"hold {hold_id} does not expire until {hold.until}")
        released = hold.evolved(
            released_at=self._clock.now_iso(),
            released_by=authority,
            release_basis=basis,
        )
        with self._store.session() as session:
            session.state.holds[released.id] = released
            session.record("hold.release", {"hold": released.as_dict()}, released.released_at)
        return released

    def get(self, hold_id: str) -> Hold:
        hold = self._store.state().holds.get(hold_id)
        if hold is None:
            raise NotFoundError(f"unknown hold {hold_id!r}")
        return hold

    def list(self) -> list[Hold]:
        holds = self._store.state().holds
        return [holds[key] for key in sorted(holds)]

    def active(self) -> list[Hold]:
        return [hold for hold in self.list() if hold.active]

    def review(self, hold_id: str) -> dict[str, Any]:
        """Re-check every registered scope entry against the live journal.

        Each entry is reported present/missing and intact/altered, and entries
        that carry an audit record are also checked against the audit chain, so
        the command log, the chain and any export of either stay entry-by-entry
        comparable.
        """

        hold = self.get(hold_id)
        committed = {entry.sequence: entry for entry in self._store.entries()}
        audit_digests = {entry.digest for entry in self._store.state().audit}
        items: list[dict[str, Any]] = []
        for scope_entry in hold.scope:
            current = committed.get(scope_entry.sequence)
            present = current is not None
            intact = bool(
                current is not None
                and current.kind == scope_entry.kind
                and _entry_digest(current) == scope_entry.digest
            )
            item: dict[str, Any] = {
                "sequence": scope_entry.sequence,
                "kind": scope_entry.kind,
                "digest": scope_entry.digest,
                "present": present,
                "intact": intact,
            }
            if scope_entry.kind == "audit.append" and present and current is not None:
                recorded = current.payload.get("entry", {})
                item["audit_chained"] = recorded.get("digest") in audit_digests
            items.append(item)
        missing = [item for item in items if not item["present"]]
        altered = [item for item in items if item["present"] and not item["intact"]]
        unchained = [item for item in items if item.get("audit_chained") is False]
        return {
            "hold_id": hold.id,
            "subject": hold.subject,
            "active": hold.active,
            "entries": items,
            "missing": len(missing),
            "altered": len(altered),
            "unchained": len(unchained),
            "intact": not (missing or altered or unchained),
        }

    def verify(self, hold_id: str) -> bool:
        return bool(self.review(hold_id)["intact"])
