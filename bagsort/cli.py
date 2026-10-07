"""Command line entry point for the control service."""

from __future__ import annotations

import argparse
import json
import logging
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer, make_server

from .app import DEFAULT_TERMINAL, Plant
from .clock import Clock
from .console.seed import seed_defaults
from .console.server import Server
from .console.version import version_string
from .demo import invariants_hold, run_demo
from .hold.auth import ROLE_HOLDER, ROLE_RELEASER, issue_credential
from .store.store import Store

LOGGER = logging.getLogger("bagsort")


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Serve concurrent control requests from a pool of worker threads."""

    daemon_threads = True


def parse_address(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if not separator or not port.isdigit():
        raise argparse.ArgumentTypeError("address must look like host:port")
    return host or "0.0.0.0", int(port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bagsort", description="line control service")
    parser.add_argument("--state", default="var/state.json", help="journal snapshot path")
    parser.add_argument("--terminal", default=DEFAULT_TERMINAL, help="terminal namespace")
    parser.add_argument("--version", action="store_true", help="print the build version and exit")
    commands = parser.add_subparsers(dest="command")

    serve = commands.add_parser("serve", help="run the JSON control console")
    serve.add_argument("--addr", default=":8080", help="listen address as host:port")
    serve.add_argument("--seed", action="store_true", help="seed default lanes and flights")
    serve.add_argument("--persist-on-start", action="store_true", help="write a snapshot first")

    demo = commands.add_parser("demo", help="run the deterministic scenario")
    demo.add_argument("--cycles", type=int, default=6, help="bags to check in")
    demo.add_argument("--persist", action="store_true", help="write a snapshot afterwards")

    commands.add_parser("report", help="print the plant report")
    commands.add_parser("status", help="print the store status")
    commands.add_parser("export", help="print audit and sort records as CSV")

    seed = commands.add_parser("seed", help="seed default lanes and flights")
    seed.add_argument("--persist", action="store_true", help="write a snapshot afterwards")

    reset = commands.add_parser("reset", help="clear the journal")
    reset.add_argument("--persist", action="store_true", help="write the empty snapshot")

    token = commands.add_parser("hold-token", help="mint a signed hold credential")
    token.add_argument("--name", required=True, help="officer principal name")
    token.add_argument("--role", choices=(ROLE_HOLDER, ROLE_RELEASER), required=True)

    place = commands.add_parser("hold-place", help="place a forensic hold")
    place.add_argument("--matter", required=True)
    place.add_argument("--bag", action="append", default=[], help="bag id, repeatable")
    place.add_argument("--flight", action="append", default=[], help="flight id, repeatable")
    place.add_argument("--sequence", action="append", type=int, default=[])
    place.add_argument("--anchor", choices=("event_time", "matter_close"), default="event_time")
    place.add_argument("--event-at", default="", help="incident time, default now")
    place.add_argument("--days", type=int, default=90, help="retention days from event")
    place.add_argument("--rationale", default="")
    place.add_argument("--credential", required=True)

    commands.add_parser("hold-list", help="list forensic holds")
    commands.add_parser("hold-storage", help="show retained storage and reclaimable bytes")

    release = commands.add_parser("hold-release", help="release a hold with a basis")
    release.add_argument("hold_id")
    release.add_argument("--basis", required=True)
    release.add_argument("--authorization", required=True)
    release.add_argument("--credential", required=True)

    extend = commands.add_parser("hold-extend", help="extend an event-time hold")
    extend.add_argument("hold_id")
    extend.add_argument("--days", required=True, type=int)
    extend.add_argument("--basis", required=True)
    extend.add_argument("--credential", required=True)

    verify = commands.add_parser("hold-verify", help="re-check a hold item by item")
    verify.add_argument("hold_id")

    compact = commands.add_parser("compact", help="compact unretained history")
    compact.add_argument("--credential", required=True)
    return parser


def _load_store(path: str) -> Store:
    return Store.open(path)


def _build(store: Store, terminal: str) -> Plant:
    return Plant.build(store, terminal=terminal, clock=Clock())


def _command_serve(store: Store, plant: Plant, args: argparse.Namespace) -> int:
    if args.seed:
        seed_defaults(plant)
    if args.persist_on_start:
        store.persist()
    host, port = parse_address(args.addr)
    application = Server(plant)
    with make_server(host, port, application, server_class=ThreadingWSGIServer) as httpd:
        LOGGER.info("control console listening on %s:%d", host, port)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            LOGGER.info("control console stopped")
    if args.seed:
        store.persist()
    return 0


def _command_demo(store: Store, plant: Plant, args: argparse.Namespace) -> int:
    summary = run_demo(plant, cycles=args.cycles)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    if args.persist:
        store.persist()
    return 0 if invariants_hold(summary) else 1


def _command_report(plant: Plant) -> int:
    print(plant.report.text(), end="")
    return 0


def _command_status(store: Store, plant: Plant) -> int:
    payload = {
        "path": store.path,
        "watermark": store.watermark,
        "dirty": store.dirty(),
        "audit_intact": plant.audit.verify(),
        "stats": store.stats(),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _command_export(plant: Plant) -> int:
    from .reporting import csv_export

    print(csv_export.render(csv_export.AUDIT_COLUMNS, csv_export.audit_rows(plant.audit.entries())))
    return 0


def _command_seed(store: Store, plant: Plant, args: argparse.Namespace) -> int:
    seeded = seed_defaults(plant)
    print(json.dumps(seeded, ensure_ascii=False, sort_keys=True))
    if args.persist:
        store.persist()
    return 0


def _command_reset(store: Store, plant: Plant, args: argparse.Namespace) -> int:
    plant.reset()
    if args.persist:
        store.persist()
    print(json.dumps({"status": "reset", "watermark": store.watermark}, sort_keys=True))
    return 0


def _command_token(args: argparse.Namespace) -> int:
    clock = Clock()
    token = issue_credential(args.name, args.role, clock.now_iso(), "bagsort-dev-hold-secret")
    print(token)
    return 0


def _command_hold_place(store: Store, plant: Plant, args: argparse.Namespace) -> int:
    scope = []
    if args.bag:
        scope.append({"kind": "bag", "ids": args.bag})
    if args.flight:
        scope.append({"kind": "flight", "ids": args.flight})
    if args.sequence:
        scope.append({"kind": "sequence", "sequences": args.sequence})
    hold = plant.holds.place(
        matter=args.matter,
        scopes=scope,
        credential=args.credential,
        rationale=args.rationale,
        anchor=args.anchor,
        event_at=args.event_at,
        retention_days=args.days,
    )
    print(json.dumps(hold.as_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _command_hold_list(plant: Plant) -> int:
    print(
        json.dumps(
            [hold.as_dict() for hold in plant.holds.list()],
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _command_hold_storage(plant: Plant) -> int:
    print(json.dumps(plant.holds.storage_review(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _command_hold_release(plant: Plant, args: argparse.Namespace) -> int:
    hold = plant.holds.release(
        args.hold_id, args.credential, args.basis, args.authorization
    )
    print(json.dumps(hold.as_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _command_hold_extend(plant: Plant, args: argparse.Namespace) -> int:
    hold = plant.holds.extend(args.hold_id, args.days, args.credential, args.basis)
    print(json.dumps(hold.as_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _command_hold_verify(plant: Plant, args: argparse.Namespace) -> int:
    report = plant.holds.verify_hold(args.hold_id)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["intact"] else 1


def _command_compact(plant: Plant, args: argparse.Namespace) -> int:
    print(json.dumps(plant.holds.compact(args.credential), ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(version_string())
        return 0

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    store = _load_store(args.state)
    plant = _build(store, args.terminal)

    if args.command in (None, "serve"):
        if args.command is None:
            args.addr = ":8080"
            args.seed = False
            args.persist_on_start = False
        return _command_serve(store, plant, args)
    if args.command == "demo":
        return _command_demo(store, plant, args)
    if args.command == "report":
        return _command_report(plant)
    if args.command == "status":
        return _command_status(store, plant)
    if args.command == "export":
        return _command_export(plant)
    if args.command == "seed":
        return _command_seed(store, plant, args)
    if args.command == "reset":
        return _command_reset(store, plant, args)
    if args.command == "hold-token":
        return _command_token(args)
    if args.command == "hold-place":
        return _command_hold_place(store, plant, args)
    if args.command == "hold-list":
        return _command_hold_list(plant)
    if args.command == "hold-storage":
        return _command_hold_storage(plant)
    if args.command == "hold-release":
        return _command_hold_release(plant, args)
    if args.command == "hold-extend":
        return _command_hold_extend(plant, args)
    if args.command == "hold-verify":
        return _command_hold_verify(plant, args)
    if args.command == "compact":
        return _command_compact(plant, args)
    parser.error(f"unknown command {args.command!r}")
    return 2
