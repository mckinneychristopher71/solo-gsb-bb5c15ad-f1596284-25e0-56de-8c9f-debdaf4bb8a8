"""Observation remediation planning against a saved analysis version.

Given a batch of **observations** — each an IPv4/IPv6 address plus the action
it *should* resolve to (``permit``/``deny``) — and a set of **candidate
rule_ids** of the saved version, this module searches for the cheapest way to
make every observation resolve to its expected action under the version's own
forwarding semantics.

Candidate operations
--------------------
Each candidate rule independently gets exactly one of three operations:

* ``keep``    : leave the rule untouched (the no-change default);
* ``disable`` : remove the rule from the ruleset (it stops deciding anything,
  so longer-prefix survivors and then shorter-prefix ancestors take over);
* ``flip``    : toggle the rule's action (``permit`` <-> ``deny``) while
  keeping its CIDR, priority, source tag and submission position.

Recomputation semantics
-----------------------
Every operation set is scored by replaying the engine's forwarding decision
for each observed address on the modified ruleset — **longest prefix wins**,
same-CIDR ties go to the smallest ``priority`` number, then the original
submission order (``index``) — exactly the attribution semantics of the
traffic audit.  Flipping never changes *which* rule wins (only its action);
disabling removes the rule from the chain, so the next surviving entry
decides.  An observation is **satisfied** only when a rule actually wins and
its (possibly flipped) action equals the expected one: an address left
**unmatched** (``none``) is never treated as ``permit`` — nor as ``deny`` —
so it satisfies no expectation.

Plan selection
--------------
Among all satisfying operation sets the winner is, in order:

1. **fewest changed rules** (``disable`` + ``flip`` count; ``keep`` is free);
2. **fewest disables** (a flip is preferred over taking a rule out of
   service);
3. the **lexicographically smallest operation sequence**: the changed rules'
   ``(rule_id, operation)`` pairs sorted by ``rule_id`` and compared element
   by element (``"disable" < "flip"``).

With at most 8 candidates the search space is bounded by 3^8 operation sets,
enumerated level by level (0 changes, 1 change, ...); the first level holding
a satisfying set yields the optimum, so deeper levels are never explored.
If the unmodified ruleset already satisfies every observation the plan is the
**empty plan** (no operations); if no operation set satisfies every
observation the plan is **null**.  The request is all-or-nothing: any invalid
IP, duplicated candidate or unknown candidate rule_id rejects the whole batch
(:class:`RemediationError`) with every problem listed at once.  Read-only:
nothing is persisted and the saved version is never modified.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from itertools import combinations, product
from typing import Any

from .simulate import rebuild_input_rules

Address = ipaddress._BaseAddress
Network = ipaddress._BaseNetwork

#: The three per-candidate operations; ``keep`` is the implicit default.
OP_KEEP = "keep"
OP_DISABLE = "disable"
OP_FLIP = "flip"

#: Action toggle applied by ``flip``.
_FLIPPED = {"permit": "deny", "deny": "permit"}


class RemediationError(Exception):
    """The remediation request is invalid as a whole.

    ``issues`` lists every offending observation/candidate (deterministic
    order), so a client can correct all problems at once.
    """

    def __init__(self, issues: list[str]):
        self.issues = issues
        super().__init__("; ".join(issues))


@dataclass(frozen=True)
class _Rule:
    """One stored rule with its parsed network (submission order = index)."""

    index: int
    rule_id: str
    network: Network
    action: str
    priority: int


def _load_rules(base_rules: list[dict[str, Any]]) -> list[_Rule]:
    return [
        _Rule(
            index=index,
            rule_id=raw["rule_id"],
            network=ipaddress.ip_network(raw["cidr"]),
            action=raw["action"],
            priority=raw["priority"],
        )
        for index, raw in enumerate(base_rules)
    ]


def _parse_addresses(
    observations: list[dict[str, Any]],
) -> tuple[list[Address | None], list[str]]:
    """Parse every observation's IP; failures are collected, not raised.

    Unparseable observations leave a ``None`` hole (the caller raises on the
    collected issues before the addresses are used).
    """
    issues: list[str] = []
    addresses: list[Address | None] = []
    for seq, obs in enumerate(observations):
        try:
            addresses.append(ipaddress.ip_address(obs["ip"]))
        except ValueError:
            issues.append(
                f"observation #{seq + 1}: invalid IP address {obs['ip']!r}; "
                "expected a plain IPv4 or IPv6 address (no prefix length)"
            )
            addresses.append(None)
    return addresses, issues


def _validate_candidates(
    candidate_ids: list[str], base_ids: set[str]
) -> tuple[list[str], list[str]]:
    """Check distinctness and existence; return (deduped ids, issues)."""
    issues: list[str] = []
    seen: set[str] = set()
    reported_dupes: set[str] = set()
    unique: list[str] = []
    for rule_id in candidate_ids:
        if rule_id in seen:
            if rule_id not in reported_dupes:  # report each duplicated id once
                reported_dupes.add(rule_id)
                issues.append(
                    f"candidate rule_id {rule_id!r} is listed more than once; "
                    "candidates must be distinct"
                )
            continue
        seen.add(rule_id)
        unique.append(rule_id)
    for rule_id in unique:
        if rule_id not in base_ids:
            issues.append(
                f"candidate rule_id {rule_id!r} does not match a rule of the "
                "base version"
            )
    return unique, issues


def _match_chain(address: Address, rules: list[_Rule]) -> list[_Rule]:
    """Every rule covering ``address``, in winning order.

    Longest prefix first; same-CIDR rules (necessarily the same network) are
    ordered by ``(priority, index)`` exactly like the engine, so the first
    entry is the current winner and disabling entries walks the chain down.
    """
    covering = [
        rule
        for rule in rules
        if rule.network.version == address.version and address in rule.network
    ]
    covering.sort(key=lambda r: (-r.network.prefixlen, r.priority, r.index))
    return covering


def _winner_under(
    chain: list[_Rule], ops: dict[str, str]
) -> tuple[_Rule, str] | None:
    """Winning rule and its effective action under the operation set.

    Disabled rules drop out of the chain; the first surviving entry wins and
    its action is toggled when it is flipped.  ``None`` means no rule
    survives: the address is unmatched (``none``), which satisfies nothing.
    """
    for rule in chain:
        op = ops.get(rule.rule_id, OP_KEEP)
        if op == OP_DISABLE:
            continue
        action = _FLIPPED[rule.action] if op == OP_FLIP else rule.action
        return rule, action
    return None


def _satisfied(chain: list[_Rule], expected: str, ops: dict[str, str]) -> bool:
    outcome = _winner_under(chain, ops)
    return outcome is not None and outcome[1] == expected


def _search(
    chains: list[list[_Rule]],
    expected: list[str],
    candidate_ids: list[str],
) -> dict[str, str] | None:
    """Cheapest operation set satisfying every observation, or ``None``.

    Operation sets are enumerated by ascending change count; within the first
    feasible level the best set wins by (fewest disables, lexicographically
    smallest sorted ``(rule_id, operation)`` sequence).
    """
    k = len(candidate_ids)
    for n_changes in range(k + 1):
        best: tuple[tuple[Any, ...], dict[str, str]] | None = None
        for subset in combinations(candidate_ids, n_changes):
            for op_seq in product((OP_DISABLE, OP_FLIP), repeat=n_changes):
                ops = dict(zip(subset, op_seq))
                if not all(
                    _satisfied(chain, exp, ops) for chain, exp in zip(chains, expected)
                ):
                    continue
                sequence = tuple(sorted(ops.items()))
                key = (n_changes, op_seq.count(OP_DISABLE), sequence)
                if best is None or key < best[0]:
                    best = (key, ops)
        if best is not None:
            return best[1]
    return None


def plan_remediation(
    base: dict[str, Any],
    observations: list[dict[str, Any]],
    candidate_ids: list[str],
) -> dict[str, Any]:
    """Plan the cheapest candidate operations satisfying ``observations``.

    ``observations`` carry ``ip`` / ``action`` (already normalized);
    ``candidate_ids`` are the caller-chosen rule ids of the saved version
    ``base``.  Returns a response-shaped dict (see module docstring).  Raises
    :class:`RemediationError` when any observation IP is invalid, or any
    candidate is duplicated or unknown; the batch is all-or-nothing.
    """
    base_rules_raw = rebuild_input_rules(base)
    rules = _load_rules(base_rules_raw)
    rule_by_id = {r.rule_id: r for r in rules}

    # The whole batch is validated before any search: every offending
    # observation and candidate is reported at once.
    parsed, issues = _parse_addresses(observations)
    candidates, candidate_issues = _validate_candidates(
        candidate_ids, set(rule_by_id)
    )
    issues.extend(candidate_issues)
    if issues:
        raise RemediationError(issues)
    # No issues -> every observation parsed; the None holes cannot remain.
    addresses = [a for a in parsed if a is not None]

    chains = [_match_chain(address, rules) for address in addresses]
    expected = [obs["action"] for obs in observations]

    ops = _search(chains, expected, candidates)

    result: dict[str, Any] = {
        "analysis_id": base.get("id"),
        "ruleset_hash": base.get("ruleset_hash"),
        "analyzer_version": base.get("analyzer_version"),
        "observation_count": len(observations),
        "candidates": candidates,
        "solved": ops is not None,
        "plan": None,
    }
    if ops is None:
        return result

    operations = []
    for rule_id, op in sorted(ops.items()):
        rule = rule_by_id[rule_id]
        operations.append(
            {
                "rule_id": rule_id,
                "operation": op,
                "cidr": str(rule.network),
                "from_action": rule.action,
                "to_action": None if op == OP_DISABLE else _FLIPPED[rule.action],
            }
        )

    outcomes = []
    for seq, (address, obs, chain) in enumerate(zip(addresses, observations, chains)):
        outcome = _winner_under(chain, ops)
        assert outcome is not None  # a returned plan satisfies every observation
        winner, action = outcome
        outcomes.append(
            {
                "seq": seq,
                "ip": str(address),
                "ip_version": address.version,
                "expected_action": obs["action"],
                "winner_rule_id": winner.rule_id,
                "action": action,
                "satisfied": action == obs["action"],
            }
        )

    result["plan"] = {
        "operations": operations,
        "changed_rules": len(ops),
        "disabled_rules": sum(1 for op in ops.values() if op == OP_DISABLE),
        "flipped_rules": sum(1 for op in ops.values() if op == OP_FLIP),
        "observations": outcomes,
    }
    return result
