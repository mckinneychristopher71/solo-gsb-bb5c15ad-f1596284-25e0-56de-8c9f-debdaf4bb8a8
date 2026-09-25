"""End-to-end tests for POST /api/analyses/{id}/remediation-plan."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app import db


@pytest.fixture()
def client() -> TestClient:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="ppa-test-rem-")
    os.close(fd)
    os.remove(path)  # let sqlite create it
    db.reset_db(path)
    from app.main import app

    with TestClient(app) as c:
        yield c
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


def _save(client: TestClient, rules: list[dict], name: str | None = None) -> str:
    body: dict = {"rules": rules}
    if name is not None:
        body["name"] = name
    r = client.post("/api/analyze", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["persisted"] is True
    return r.json()["id"]


def _remediate(client: TestClient, aid: str, observations: list[dict], candidates: list[str]) -> dict:
    r = client.post(
        f"/api/analyses/{aid}/remediation-plan",
        json={"observations": observations, "candidates": candidates},
    )
    assert r.status_code == 200, r.text
    return r.json()


# permit /8 -> deny /16 -> permit /24: three nested decisions to repair.
NESTED_RULES = [
    {"rule_id": "a", "cidr": "10.0.0.0/8", "action": "permit", "priority": 100, "source_tag": "core"},
    {"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200, "source_tag": "edge"},
    {"rule_id": "c", "cidr": "10.1.1.0/24", "action": "permit", "priority": 50, "source_tag": "lab"},
]


# ---------------------------------------------------------------------------
# Plan selection
# ---------------------------------------------------------------------------
def test_already_satisfied_returns_empty_plan(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES, name="nested")

    payload = _remediate(
        client,
        aid,
        [
            {"ip": "10.1.1.7", "action": "permit"},   # c already permits
            {"ip": "10.1.2.9", "action": "deny"},     # b already denies
            {"ip": "10.2.3.4", "action": "permit"},   # a already permits
        ],
        ["a", "b", "c"],
    )

    assert payload["analysis_id"] == aid
    assert payload["observation_count"] == 3
    assert payload["candidates"] == ["a", "b", "c"]
    assert payload["solved"] is True
    plan = payload["plan"]
    assert plan["operations"] == []
    assert plan["changed_rules"] == 0
    assert plan["disabled_rules"] == 0
    assert plan["flipped_rules"] == 0
    # Observations are still recomputed and reported under the unchanged ruleset.
    outcomes = plan["observations"]
    assert [o["seq"] for o in outcomes] == [0, 1, 2]
    assert outcomes[0]["winner_rule_id"] == "c"
    assert outcomes[0]["action"] == "permit"
    assert outcomes[1]["winner_rule_id"] == "b"
    assert outcomes[1]["action"] == "deny"
    assert outcomes[2]["winner_rule_id"] == "a"
    assert all(o["satisfied"] is True for o in outcomes)


def test_single_flip_fixes_mismatched_observation(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    payload = _remediate(
        client, aid, [{"ip": "10.1.2.9", "action": "permit"}], ["b"]
    )

    assert payload["solved"] is True
    plan = payload["plan"]
    assert plan["operations"] == [
        {
            "rule_id": "b",
            "operation": "flip",
            "cidr": "10.1.0.0/16",
            "from_action": "deny",
            "to_action": "permit",
        }
    ]
    assert plan["changed_rules"] == 1
    assert plan["disabled_rules"] == 0
    assert plan["flipped_rules"] == 1
    outcome = plan["observations"][0]
    assert outcome["winner_rule_id"] == "b"
    assert outcome["action"] == "permit"
    assert outcome["expected_action"] == "permit"
    assert outcome["satisfied"] is True


def test_flip_preferred_over_disable_at_same_change_count(client: TestClient) -> None:
    # Both flipping b (b becomes permit) and disabling b (ancestor a permits)
    # satisfy the observation with one change; the plan with fewer disables wins.
    aid = _save(client, NESTED_RULES)

    payload = _remediate(
        client, aid, [{"ip": "10.1.2.9", "action": "permit"}], ["b"]
    )

    ops = payload["plan"]["operations"]
    assert [op["operation"] for op in ops] == ["flip"]
    assert payload["plan"]["disabled_rules"] == 0


def test_unmatched_is_not_treated_as_permit(client: TestClient) -> None:
    # Only one rule covers the address; disabling it would leave the address
    # unmatched.  An unmatched address must NOT count as permit, so the plan
    # must flip the rule instead of disabling it.
    aid = _save(
        client,
        [{"rule_id": "b", "cidr": "10.1.0.0/16", "action": "deny", "priority": 200}],
    )

    payload = _remediate(
        client, aid, [{"ip": "10.1.2.9", "action": "permit"}], ["b"]
    )

    assert payload["solved"] is True
    ops = payload["plan"]["operations"]
    assert ops == [
        {
            "rule_id": "b",
            "operation": "flip",
            "cidr": "10.1.0.0/16",
            "from_action": "deny",
            "to_action": "permit",
        }
    ]
    outcome = payload["plan"]["observations"][0]
    assert outcome["winner_rule_id"] == "b"
    assert outcome["action"] == "permit"


def test_uncoverable_observation_is_unsolvable(client: TestClient) -> None:
    # No rule covers the address and no candidate can add coverage (disable
    # only removes, flip only toggles): expecting permit stays unmet.
    aid = _save(client, NESTED_RULES)

    payload = _remediate(
        client, aid, [{"ip": "192.0.2.8", "action": "permit"}], ["a", "b", "c"]
    )

    assert payload["solved"] is False
    assert payload["plan"] is None


def test_unsolvable_when_winning_rule_is_not_a_candidate(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # 10.1.2.9 is decided by b; with b not among the candidates nothing can
    # change its verdict.
    payload = _remediate(
        client, aid, [{"ip": "10.1.2.9", "action": "permit"}], ["a", "c"]
    )

    assert payload["solved"] is False
    assert payload["plan"] is None


def test_unsolvable_contradictory_expectations_on_shared_winner(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # Both addresses are decided by b (deny /16): one observation is already
    # satisfied, the other needs the opposite action.  No operation set can
    # satisfy both, whatever the candidates.
    payload = _remediate(
        client,
        aid,
        [
            {"ip": "10.1.2.9", "action": "permit"},
            {"ip": "10.1.2.10", "action": "deny"},
        ],
        ["a", "b", "c"],
    )

    assert payload["solved"] is False
    assert payload["plan"] is None


def test_multiple_observations_minimal_change_count(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # Two mismatched observations with distinct winners need exactly two
    # flips; a third already-satisfied observation must stay satisfied.
    payload = _remediate(
        client,
        aid,
        [
            {"ip": "10.1.2.9", "action": "permit"},   # b: deny -> permit
            {"ip": "10.1.1.7", "action": "deny"},     # c: permit -> deny
            {"ip": "10.2.3.4", "action": "permit"},   # a: already permit
        ],
        ["a", "b", "c"],
    )

    assert payload["solved"] is True
    plan = payload["plan"]
    assert plan["changed_rules"] == 2
    assert plan["flipped_rules"] == 2
    assert plan["disabled_rules"] == 0
    # Operations are reported sorted by rule_id.
    assert [(op["rule_id"], op["operation"]) for op in plan["operations"]] == [
        ("b", "flip"),
        ("c", "flip"),
    ]
    outcomes = plan["observations"]
    assert outcomes[0]["winner_rule_id"] == "b"
    assert outcomes[0]["action"] == "permit"
    assert outcomes[1]["winner_rule_id"] == "c"
    assert outcomes[1]["action"] == "deny"
    assert outcomes[2]["winner_rule_id"] == "a"
    assert outcomes[2]["action"] == "permit"


def test_shared_winner_fixed_by_one_flip(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # Two mismatched observations decided by the same rule b: a single flip
    # fixes both (fewest changed rules).
    payload = _remediate(
        client,
        aid,
        [
            {"ip": "10.1.2.9", "action": "permit"},
            {"ip": "10.1.3.9", "action": "permit"},
        ],
        ["a", "b", "c"],
    )

    plan = payload["plan"]
    assert plan["changed_rules"] == 1
    assert plan["operations"][0]["rule_id"] == "b"
    assert plan["operations"][0]["operation"] == "flip"
    assert all(o["winner_rule_id"] == "b" for o in plan["observations"])
    assert all(o["action"] == "permit" for o in plan["observations"])


def test_same_cidr_duplicate_takes_over_after_disable_but_flip_wins(client: TestClient) -> None:
    # Same CIDR twice: x wins by priority, y is the losing duplicate.
    # Expecting deny: flipping x (1 change, 0 disables) beats disabling x
    # (1 change, 1 disable; y would take over with deny).
    aid = _save(
        client,
        [
            {"rule_id": "x", "cidr": "10.1.0.0/24", "action": "permit", "priority": 100},
            {"rule_id": "y", "cidr": "10.1.0.0/24", "action": "deny", "priority": 200},
        ],
    )

    payload = _remediate(
        client, aid, [{"ip": "10.1.0.7", "action": "deny"}], ["x", "y"]
    )

    plan = payload["plan"]
    assert plan["operations"] == [
        {
            "rule_id": "x",
            "operation": "flip",
            "cidr": "10.1.0.0/24",
            "from_action": "permit",
            "to_action": "deny",
        }
    ]
    assert plan["disabled_rules"] == 0
    outcome = plan["observations"][0]
    assert outcome["winner_rule_id"] == "x"
    assert outcome["action"] == "deny"


def test_disable_is_never_part_of_a_worse_plan(client: TestClient) -> None:
    # Expecting permit where b denies and ancestor a permits: disabling b
    # would work, but the flip (fewer disables) is strictly preferred; a plan
    # changing two rules is never chosen over the single flip.
    aid = _save(client, NESTED_RULES)

    payload = _remediate(
        client, aid, [{"ip": "10.1.2.9", "action": "permit"}], ["a", "b", "c"]
    )

    plan = payload["plan"]
    assert plan["changed_rules"] == 1
    assert plan["operations"][0] == {
        "rule_id": "b",
        "operation": "flip",
        "cidr": "10.1.0.0/16",
        "from_action": "deny",
        "to_action": "permit",
    }


def test_ipv6_observations(client: TestClient) -> None:
    aid = _save(
        client,
        [
            {"rule_id": "v6", "cidr": "2001:db8::/32", "action": "deny", "priority": 100},
            {"rule_id": "v6h", "cidr": "2001:db8:1::/48", "action": "permit", "priority": 900},
        ],
    )

    payload = _remediate(
        client,
        aid,
        [
            {"ip": "2001:db8:2::7", "action": "permit"},  # v6: deny -> permit
            {"ip": "2001:db8:1::7", "action": "permit"},  # v6h: already permit
        ],
        ["v6", "v6h"],
    )

    assert payload["solved"] is True
    plan = payload["plan"]
    assert plan["operations"] == [
        {
            "rule_id": "v6",
            "operation": "flip",
            "cidr": "2001:db8::/32",
            "from_action": "deny",
            "to_action": "permit",
        }
    ]
    outcomes = plan["observations"]
    assert outcomes[0]["ip_version"] == 6
    assert outcomes[0]["winner_rule_id"] == "v6"
    assert outcomes[0]["action"] == "permit"
    assert outcomes[1]["winner_rule_id"] == "v6h"


def test_action_aliases_are_normalized(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    payload = _remediate(
        client, aid, [{"ip": "10.1.2.9", "action": "ALLOW"}], ["b"]
    )

    outcome = payload["plan"]["observations"][0]
    assert outcome["expected_action"] == "permit"
    assert outcome["action"] == "permit"


def test_max_batch_sizes_accepted(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    # 20 observations (the maximum), all sharing winner b: one flip fixes all.
    observations = [{"ip": f"10.1.2.{i}", "action": "permit"} for i in range(20)]
    payload = _remediate(client, aid, observations, ["a", "b", "c"])
    assert payload["solved"] is True
    assert payload["plan"]["changed_rules"] == 1
    assert len(payload["plan"]["observations"]) == 20


def test_max_eight_candidates_accepted(client: TestClient) -> None:
    rules = [
        {"rule_id": f"r{i}", "cidr": f"10.{i}.0.0/16", "action": "deny", "priority": 100}
        for i in range(8)
    ]
    aid = _save(client, rules)

    payload = _remediate(
        client,
        aid,
        [{"ip": "10.3.0.7", "action": "permit"}],
        [f"r{i}" for i in range(8)],
    )
    assert payload["solved"] is True
    assert payload["candidates"] == [f"r{i}" for i in range(8)]
    assert payload["plan"]["operations"] == [
        {
            "rule_id": "r3",
            "operation": "flip",
            "cidr": "10.3.0.0/16",
            "from_action": "deny",
            "to_action": "permit",
        }
    ]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def test_batch_size_limits(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    url = f"/api/analyses/{aid}/remediation-plan"

    # 0 / 21 observations -> 422.
    assert client.post(url, json={"observations": [], "candidates": ["b"]}).status_code == 422
    too_many = [{"ip": f"10.1.2.{i}", "action": "permit"} for i in range(21)]
    assert client.post(url, json={"observations": too_many, "candidates": ["b"]}).status_code == 422

    # 0 / 9 candidates -> 422.
    one_obs = [{"ip": "10.1.2.9", "action": "permit"}]
    assert client.post(url, json={"observations": one_obs, "candidates": []}).status_code == 422
    assert (
        client.post(
            url,
            json={"observations": one_obs, "candidates": ["a", "b", "c", "d", "e", "f", "g", "h", "i"]},
        ).status_code
        == 422
    )


def test_duplicate_and_unknown_candidates_rejected_with_all_issues(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    r = client.post(
        f"/api/analyses/{aid}/remediation-plan",
        json={
            "observations": [{"ip": "10.1.2.9", "action": "permit"}],
            "candidates": ["b", "zz", "b", "qq"],
        },
    )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["error"] == "invalid_remediation"
    assert len(body["issues"]) == 3
    assert any("'b' is listed more than once" in i for i in body["issues"])
    assert any("'zz' does not match" in i for i in body["issues"])
    assert any("'qq' does not match" in i for i in body["issues"])


def test_invalid_ips_reject_whole_batch_with_all_issues(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    r = client.post(
        f"/api/analyses/{aid}/remediation-plan",
        json={
            "observations": [
                {"ip": "10.1.2.9", "action": "permit"},
                {"ip": "10.0.0.5/24", "action": "permit"},   # CIDR, not an address
                {"ip": "not-an-ip", "action": "deny"},
            ],
            "candidates": ["b"],
        },
    )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["error"] == "invalid_remediation"
    assert len(body["issues"]) == 2
    assert "observation #2" in body["issues"][0]
    assert "10.0.0.5/24" in body["issues"][0]
    assert "observation #3" in body["issues"][1]
    assert "not-an-ip" in body["issues"][1]


def test_invalid_ip_and_unknown_candidate_reported_together(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)

    r = client.post(
        f"/api/analyses/{aid}/remediation-plan",
        json={
            "observations": [{"ip": "not-an-ip", "action": "permit"}],
            "candidates": ["zz"],
        },
    )
    assert r.status_code == 400, r.text
    body = r.json()
    assert body["error"] == "invalid_remediation"
    assert len(body["issues"]) == 2
    assert any("observation #1" in i for i in body["issues"])
    assert any("'zz'" in i for i in body["issues"])


def test_field_level_validation_errors(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    url = f"/api/analyses/{aid}/remediation-plan"
    one_obs = [{"ip": "10.1.2.9", "action": "permit"}]

    # Unknown action -> 422 (same convention as rule actions).
    assert (
        client.post(url, json={"observations": [{"ip": "10.1.2.9", "action": "maybe"}], "candidates": ["b"]}).status_code
        == 422
    )
    # Missing / empty / blank fields.
    assert client.post(url, json={"candidates": ["b"]}).status_code == 422
    assert client.post(url, json={"observations": one_obs}).status_code == 422
    assert client.post(url, json={}).status_code == 422
    assert (
        client.post(url, json={"observations": [{"ip": "  ", "action": "permit"}], "candidates": ["b"]}).status_code
        == 422
    )
    assert (
        client.post(url, json={"observations": one_obs, "candidates": ["  "]}).status_code == 422
    )
    # Unknown extra fields -> 422.
    assert (
        client.post(url, json={"observations": one_obs, "candidates": ["b"], "note": "x"}).status_code
        == 422
    )
    assert (
        client.post(
            url,
            json={"observations": [{"ip": "10.1.2.9", "action": "permit", "note": "x"}], "candidates": ["b"]},
        ).status_code
        == 422
    )


def test_unknown_analysis_returns_404(client: TestClient) -> None:
    r = client.post(
        "/api/analyses/an_0000000000000000/remediation-plan",
        json={"observations": [{"ip": "10.1.2.9", "action": "permit"}], "candidates": ["b"]},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Read-only contract
# ---------------------------------------------------------------------------
def test_remediation_is_read_only_and_deterministic(client: TestClient) -> None:
    aid = _save(client, NESTED_RULES)
    observations = [
        {"ip": "10.1.2.9", "action": "permit"},
        {"ip": "10.1.1.7", "action": "deny"},
    ]

    before = client.get("/api/analyses").json()
    first = _remediate(client, aid, observations, ["a", "b", "c"])
    second = _remediate(client, aid, observations, ["a", "b", "c"])
    after = client.get("/api/analyses").json()

    assert first == second
    assert after["total"] == before["total"] == 1
    assert [a["id"] for a in after["analyses"]] == [aid]

    # The saved version itself is untouched.
    saved = client.get(f"/api/analyses/{aid}").json()
    assert saved["summary"]["rule_count"] == 3
    actions = {r["rule_id"]: r["action"] for r in saved["rules"]}
    assert actions == {"a": "permit", "b": "deny", "c": "permit"}

    # The publication pointer is untouched as well.
    assert client.get("/api/active").json() == {"active_id": None, "revision": 0}
