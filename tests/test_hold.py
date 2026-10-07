"""Forensic holds: placement, release, grooming guards, compaction and review."""

from __future__ import annotations

import json

import pytest

from bagsort.app import Plant
from bagsort.clock import Clock
from bagsort.errors import ConflictError, NotFoundError, ValidationError
from bagsort.store.store import Store
from tests.support import check_in

RETENTION = 3600


def place_hold(plant, subject, retention=RETENTION, authority="security-office"):
    return plant.place_hold(subject, "lost baggage dispute", authority, retention)


def sorted_bags(plant, flight_id, count=2):
    bags = check_in(plant, flight_id, count)
    for bag in bags:
        plant.push_bag(bag.id, "T1-CHA")
    return bags


def call(server, method, path, payload=None):
    response = server.call(method, path, payload)
    if response.content_type.startswith("application/json"):
        return response.status, json.loads(response.body)
    return response.status, response.body.decode("utf-8")


def test_place_registers_scope_and_replays_after_restart(plant, flight):
    bags = sorted_bags(plant, flight.id)
    hold = place_hold(plant, bags[0].id)

    assert hold.active is True
    assert hold.until > hold.event_at
    kinds = {entry.kind for entry in hold.scope}
    assert {"bag.put", "sort.record", "audit.append"} <= kinds
    assert plant.store.kinds()["hold.place"] == 1
    assert plant.store.state().holds[hold.id].scope == hold.scope

    plant.store.persist()
    restored = Plant.build(Store.open(plant.store.path), clock=Clock())
    replayed = restored.holds.get(hold.id)
    assert replayed == hold
    assert restored.holds.verify(hold.id) is True


def test_release_requires_expiry_authority_and_basis(plant, flight):
    bag = sorted_bags(plant, flight.id, 1)[0]
    hold = place_hold(plant, bag.id)

    with pytest.raises(ConflictError):
        plant.release_hold(hold.id, "security-office", "case closed")
    with pytest.raises(ConflictError):
        plant.holds.release(hold.id, "", "case closed")

    plant.clock.advance(RETENTION + 1)
    with pytest.raises(ConflictError):
        plant.release_hold(hold.id, "impostor", "case closed")
    with pytest.raises(ValidationError):
        plant.release_hold(hold.id, "security-office", "")

    released = plant.release_hold(hold.id, "security-office", "case closed")
    assert released.active is False
    assert released.released_by == "security-office"
    assert released.release_basis == "case closed"
    with pytest.raises(ConflictError):
        plant.release_hold(hold.id, "security-office", "case closed again")
    with pytest.raises(NotFoundError):
        plant.release_hold("hold-999999", "security-office", "case closed")


def test_storage_pressure_is_not_a_release_ground(plant, flight):
    bag = sorted_bags(plant, flight.id, 1)[0]
    hold = place_hold(plant, bag.id)
    with pytest.raises(ConflictError):
        plant.release_hold(hold.id, "security-office", "storage pressure")


def test_duplicate_active_hold_on_a_subject_is_rejected(plant, flight):
    bag = sorted_bags(plant, flight.id, 1)[0]
    place_hold(plant, bag.id)
    with pytest.raises(ConflictError):
        place_hold(plant, bag.id)
    with pytest.raises(ValidationError):
        place_hold(plant, "")
    with pytest.raises(ValidationError):
        place_hold(plant, bag.id + "x", retention=0)


def test_grooming_cannot_touch_held_records(plant, flight):
    bags = sorted_bags(plant, flight.id)
    plant.append_transfer(flight.id, "T1-CRCR1", 1)
    hold = place_hold(plant, bags[0].id)
    flight_hold = place_hold(plant, flight.id)

    with pytest.raises(ConflictError):
        plant.belt.discard_stale(2)
    with pytest.raises(ConflictError):
        plant.book.remove(flight.id)
    with pytest.raises(ConflictError):
        plant.cancel_check_in(bags[0].id)
    with pytest.raises(ConflictError):
        plant.store.reset()

    # The other bag is not held, so its cancellation still works.
    plant.cancel_check_in(bags[1].id)
    plant.clock.advance(RETENTION + 1)
    for held in (hold, flight_hold):
        plant.release_hold(held.id, "security-office", "case closed")
    assert plant.belt.discard_stale(2) == 1
    plant.store.reset()
    assert plant.store.watermark == 0


def test_compaction_reclaims_history_but_never_held_entries(plant, flight):
    bags = sorted_bags(plant, flight.id)
    plant.append_transfer(flight.id, "T1-CRCR1", 1)
    hold = place_hold(plant, bags[0].id)
    before = plant.store.watermark + 1

    dropped = plant.compact_history(before)
    assert dropped > 0

    remaining = {entry.sequence for entry in plant.store.entries()}
    pinned = {item.sequence for item in hold.scope}
    assert pinned <= remaining, "held entries must survive compaction"
    assert all(entry.kind != "sort.record" or entry.sequence in pinned
               for entry in plant.store.entries())
    # The audit chain is never compacted and still verifies.
    assert plant.audit.count() > 0
    assert plant.audit.verify() is True
    assert plant.holds.verify(hold.id) is True
    # Entities are rebuilt identically; only history lists shrank.
    assert plant.store.state().bags.keys() == {bag.id for bag in bags}
    assert {record.bag_id for record in plant.store.state().sort_records} == {bags[0].id}


def test_review_is_entry_by_entry_and_reports_loss_after_release(plant, flight):
    bag = sorted_bags(plant, flight.id, 1)[0]
    hold = place_hold(plant, bag.id, retention=60)

    report = plant.review_hold(hold.id)
    assert report["intact"] is True and report["verified"] is True
    assert report["audit_chain_intact"] is True
    assert report["missing"] == 0 and report["altered"] == 0
    assert all(item["present"] and item["intact"] for item in report["entries"])
    chained = [item for item in report["entries"] if item["kind"] == "audit.append"]
    assert chained and all(item["audit_chained"] for item in chained)

    plant.clock.advance(61)
    plant.release_hold(hold.id, "security-office", "case closed")
    assert plant.compact_history(plant.store.watermark + 1) > 0

    report = plant.review_hold(hold.id)
    assert report["intact"] is False and report["verified"] is False
    assert report["missing"] > 0
    assert [item for item in report["entries"] if not item["present"]]


def test_hold_events_join_the_audit_chain(plant, flight):
    bag = sorted_bags(plant, flight.id, 1)[0]
    hold = place_hold(plant, bag.id, retention=60)
    plant.clock.advance(61)
    plant.release_hold(hold.id, "security-office", "case closed")

    kinds = plant.audit.by_kind()
    assert kinds["hold_place"] == 1
    assert kinds["hold_release"] == 1
    entries = plant.audit.for_subject(bag.id)
    assert any(entry.kind == "hold_place" for entry in entries)
    assert plant.audit.verify() is True


def test_hold_routes_and_export(server):
    status, _ = call(
        server, "POST", "/api/flights", {"code": "CA1234", "carousel": "CR1", "chute": "A"}
    )
    assert status == 201
    status, bag = call(
        server, "POST", "/api/bags/checkin", {"barcode": "BAG0001", "flight_id": "T1-CA1234"}
    )
    assert status == 201
    bag_id = bag["id"]

    status, hold = call(
        server,
        "POST",
        "/api/holds",
        {
            "subject": bag_id,
            "reason": "lost baggage dispute",
            "authority": "security-office",
            "retention_seconds": 3600,
        },
    )
    assert status == 201
    hold_id = hold["id"]

    status, holds = call(server, "GET", "/api/holds")
    assert status == 200 and [row["id"] for row in holds] == [hold_id]
    status, active = call(server, "GET", "/api/holds/active")
    assert status == 200 and len(active) == 1
    status, fetched = call(server, "GET", f"/api/holds/{hold_id}")
    assert status == 200 and fetched["subject"] == bag_id
    assert call(server, "GET", "/api/holds/hold-999999")[0] == 404

    status, _ = call(
        server,
        "POST",
        f"/api/holds/{hold_id}/release",
        {"authority": "security-office", "basis": "case closed"},
    )
    assert status == 409, "an unexpired hold must not be releasable"

    status, review = call(server, "GET", f"/api/holds/{hold_id}/review")
    assert status == 200
    assert review["intact"] is True and review["audit_chain_intact"] is True

    status, compacted = call(server, "POST", "/api/store/compact", {"before": 10**9})
    assert status == 200
    assert call(server, "GET", f"/api/holds/{hold_id}/review")[1]["intact"] is True

    status, csv_text = call(server, "GET", "/api/export/holds.csv")
    assert status == 200
    assert hold_id in csv_text

    status, _ = call(server, "POST", "/api/admin/reset")
    assert status == 409, "reset is barred while a hold is in force"


def test_released_hold_allows_reset_via_routes(server):
    call(server, "POST", "/api/flights", {"code": "CA1234", "carousel": "CR1", "chute": "A"})
    _, bag = call(
        server, "POST", "/api/bags/checkin", {"barcode": "BAG0001", "flight_id": "T1-CA1234"}
    )
    _, hold = call(
        server,
        "POST",
        "/api/holds",
        {
            "subject": bag["id"],
            "reason": "lost baggage dispute",
            "authority": "security-office",
            "retention_seconds": 30,
        },
    )
    server.plant.clock.advance(31)
    status, released = call(
        server,
        "POST",
        f"/api/holds/{hold['id']}/release",
        {"authority": "security-office", "basis": "case closed"},
    )
    assert status == 200 and released["active"] is False
    assert call(server, "GET", "/api/holds/active")[1] == []
    assert call(server, "POST", "/api/admin/reset")[0] == 200
