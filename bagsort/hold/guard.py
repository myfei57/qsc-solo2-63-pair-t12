"""The guard that keeps grooming hands off records under forensic hold."""

from __future__ import annotations

from bagsort.errors import ConflictError
from bagsort.model.state import State


def ensure_not_held(state: State, subject: str, action: str) -> None:
    """Bar ``action`` while an active forensic hold covers ``subject``."""

    for hold in state.holds.values():
        if hold.active and hold.subject == subject:
            raise ConflictError(
                f"{action} is barred while forensic hold {hold.id} covers {subject}"
            )
