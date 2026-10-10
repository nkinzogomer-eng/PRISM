"""Hidden-world oracle.

The solver never sees `world_table` or `hidden_id`. It only receives the answer
to each operation it requests, exactly as it would from a real system.
"""

from __future__ import annotations

from .generators import Generated


class HiddenWorldOracle:
    def __init__(self, generated: Generated):
        self._table = generated.world_table
        self._hidden = generated.hidden_id
        self.calls: list[str] = []

    def observe(self, observation_id: str) -> str:
        self.calls.append(observation_id)
        return self._table[self._hidden]["observations"][observation_id]
