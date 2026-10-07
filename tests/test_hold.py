"""Forensic hold lifecycle, immutability, release basis and compaction."""

from __future__ import annotations

import json

import pytest

from bagsort.errors import (
    AuthorizationError,
    ConflictError,
    HoldViolation,
    ValidationError,
)
from bagsort.app import Plant
from bagsort.hold import export as hold_export
from bagsort.hold.auth import ROLE_HOLDER, ROLE_RELEASER, issue_credential
from bagsort.hold.manifest import POLICY_INVESTIGATION, digest
from bagsort.store.store import Store

SECRET = "bagsort-dev-hold-secret"


def _credential(role: str, plant, name: str) -> str:
    return issue_credential(name, role, plant.clock.now_iso(), SECRET)


def _dispute(plant):
    flight = plant.register_flight("CA7777", "CR7")
    target = plant.check_in("D0001", flight.id)
    bystander = plant.check_in("D0002", flight.id)
    plant.push_bag(target.id, "C7")
    return target, bystander


def _place(plant, bag, **overrides):
    scopes = overrides.pop("scopes", [{"kind": "bag", "ids": [bag.id]}])
    params = dict(
        matter="LUGGAGE-CLAIM-77",
        scopes=scopes,
        credential=_credential(ROLE_HOLDER, plant, "alice"),
        rationale="lost bag dispute",
        anchor="event_time",
        retention_days=30,
    )
    params.update(overrides)
    return plant.holds.place(**params)


def test_place_freezes_an_itemised_sealed_manifest(plant):
    target, _ = _dispute(plant)
    hold = _place(plant, target)
    assert hold.status == "active"
    assert hold.seal
    assert hold.items and all(item.content_hash for item in hold.items)
    assert {item.subject for item in hold.items} == {target.id}
    assert hold.verify_seal()


def test_unresolved_scope_is_rejected(plant):
    target, _ = _dispute(plant)
    with pytest.raises(ValidationError):
        _place(plant, target, scopes=[{"kind": "bag", "ids": ["T1-GHOST"]}])
    with pytest.raises(ValidationError):
        _place(plant, target, scopes=[{"kind": "sequence", "sequences": [999999]}])


def test_held_bag_cannot_be_rewritten_or_removed(plant):
    target, bystander = _dispute(plant)
    _place(plant, target)
    with pytest.raises(HoldViolation):
        plant.cancel_check_in(target.id)
    with pytest.raises(HoldViolation):
        plant.divert_bag(target.id)
    # An unrelated bag keeps operating: retention is scoped, not a global lock.
    plant.cancel_check_in(bystander.id)


def test_reset_is_refused_while_a_hold_is_active(plant):
    target, _ = _dispute(plant)
    _place(plant, target)
    with pytest.raises(HoldViolation):
        plant.reset()


def test_recheck_and_clear_commands_are_guarded(plant):
    target, _ = _dispute(plant)
    plant.enqueue_recheck(target.id)
    _place(plant, target)
    with pytest.raises(HoldViolation):
        plant.recheck.clear()
    with pytest.raises(HoldViolation):
        plant.process_recheck()


def test_release_requires_releaser_role(plant):
    target, _ = _dispute(plant)
    hold = _place(plant, target)
    with pytest.raises(AuthorizationError):
        plant.holds.release(
            hold.id, _credential(ROLE_HOLDER, plant, "alice"), "basis", "order-1"
        )


def test_placing_officer_cannot_also_release(plant):
    target, _ = _dispute(plant)
    hold = _place(plant, target)
    with pytest.raises(ConflictError):
        plant.holds.release(
            hold.id, _credential(ROLE_RELEASER, plant, "alice"), "closed", "order-1"
        )


def test_release_requires_basis_and_authorization(plant):
    target, _ = _dispute(plant)
    hold = _place(plant, target)
    plant.clock.advance(31 * 24 * 3600)
    with pytest.raises(ValidationError):
        plant.holds.release(
            hold.id, _credential(ROLE_RELEASER, plant, "bob"), "", "order-1"
        )
    with pytest.raises(ValidationError):
        plant.holds.release(
            hold.id, _credential(ROLE_RELEASER, plant, "bob"), "basis", ""
        )


def test_event_time_hold_cannot_release_before_not_before_even_under_pressure(plant):
    target, _ = _dispute(plant)
    hold = _place(plant, target)
    plant.clock.advance(29 * 24 * 3600)
    with pytest.raises(ConflictError):
        plant.holds.release(
            hold.id,
            _credential(ROLE_RELEASER, plant, "bob"),
            "disk full",
            "ops-request",
        )
    plant.clock.advance(2 * 24 * 3600)
    released = plant.holds.release(
        hold.id,
        _credential(ROLE_RELEASER, plant, "bob"),
        "matter adjudicated, doc CLM-77-9",
        "court-order-42",
    )
    assert released.status == "released"
    assert released.release_basis and released.release_authorization
    assert released.released_by == "bob"


def test_matter_close_hold_has_no_not_before(plant):
    target, _ = _dispute(plant)
    hold = _place(plant, target, anchor=POLICY_INVESTIGATION, retention_days=0)
    assert hold.not_before == ""
    with pytest.raises(ConflictError):
        plant.holds.extend(hold.id, 5, _credential(ROLE_HOLDER, plant, "alice"), "b")


def test_extend_pushes_the_release_floor(plant):
    target, _ = _dispute(plant)
    hold = _place(plant, target, retention_days=10)
    extended = plant.holds.extend(
        hold.id, 20, _credential(ROLE_HOLDER, plant, "alice"), "new evidence"
    )
    assert extended.extension_days == 20
    assert extended.not_before > hold.not_before


def test_forged_credential_is_rejected(plant):
    target, _ = _dispute(plant)
    forged = issue_credential("mallory", ROLE_HOLDER, plant.clock.now_iso(), "wrong-secret")
    with pytest.raises(AuthorizationError):
        plant.holds.place(
            matter="x",
            scopes=[{"kind": "bag", "ids": [target.id]}],
            credential=forged,
        )


def test_verify_hold_checks_every_item_and_detects_loss(plant):
    target, _ = _dispute(plant)
    hold = _place(plant, target)
    report = plant.holds.verify_hold(hold.id)
    assert report["intact"] and report["items_present"] == report["items_expected"]
    # Simulate a later organisation dropping a pinned sequence out of the log.
    entries = [e for e in plant.store.entries() if e.sequence != hold.sequences[0]]
    plant.store.adopt_entries(entries)
    report = plant.holds.verify_hold(hold.id)
    assert not report["intact"]
    assert hold.sequences[0] in report["missing_sequences"]


def test_compaction_keeps_pinned_history_and_rebuilds_state(plant):
    target, bystander = _dispute(plant)
    hold = _place(plant, target, retention_days=1)
    before = plant.store.state().as_dict()
    result = plant.holds.compact(_credential(ROLE_RELEASER, plant, "bob"))
    assert result["removed"] > 0
    assert all(seq not in result["removed_sequences"] for seq in hold.sequences)
    after = plant.store.state().as_dict()
    # Only the compaction audit entry is new; every other state is identical.
    assert {key: value for key, value in after.items() if key != "audit"} == {
        key: value for key, value in before.items() if key != "audit"
    }
    assert len(after["audit"]) == len(before["audit"]) + 1
    assert after["audit"][-1]["kind"] == "hold.compacted"
    assert plant.audit.verify()
    assert plant.holds.verify_hold(hold.id)["intact"]


def test_pinned_records_survive_restart_from_disk(tmp_path):
    from tests.support import make_plant

    plant = make_plant(tmp_path)
    target, _ = _dispute(plant)
    hold = _place(plant, target, retention_days=1)
    plant.holds.compact(_credential(ROLE_RELEASER, plant, "bob"))
    plant.store.persist()

    reopened_store = Store.open(str(tmp_path / "state.json"))
    reopened = Plant.build(reopened_store, clock=plant.clock, hold_secret=SECRET)
    assert reopened.store.state().as_dict() == plant.store.state().as_dict()
    assert reopened.audit.verify()
    assert reopened.holds.verify_hold(hold.id)["intact"]


def test_export_bundle_bites_chain_log_and_manifest(plant):
    target, _ = _dispute(plant)
    hold = _place(plant, target)
    bundle = hold_export.build_bundle([hold], plant.store.entries())
    report = hold_export.verify_bundle(bundle, plant.audit.entries())
    assert report["intact"]

    tampered = json.loads(json.dumps(bundle))
    record = tampered["bundle"]["records"][0]
    record["payload"] = {**record["payload"], "tampered": True}
    bad = hold_export.verify_bundle(tampered, plant.audit.entries())
    assert not bad["records_intact"] and not bad["intact"]

    sealed_tamper = json.loads(json.dumps(bundle))
    sealed_tamper["bundle"]["manifests"][0]["matter"] = "CHANGED"
    bad_seal = hold_export.verify_bundle(sealed_tamper, plant.audit.entries())
    assert not bad_seal["seals_intact"]


def test_storage_review_attributes_the_retained_cost(plant):
    target, bystander = _dispute(plant)
    hold = _place(plant, target)
    review = plant.holds.storage_review()
    assert review["active_holds"] == 1
    assert review["pinned_entries"] == len(hold.sequences)
    assert review["pinned_bytes"] > 0
    assert review["pinned_bytes"] <= review["journal_bytes"]
    assert review["by_hold"][0]["id"] == hold.id
