from prism.optimal import solve_expected
from prism.reference import FiniteProblem, Hypothesis, Observation
from prism.replay import Trace, replay


def test_replay_reconstructs_state():
    p = FiniteProblem(
        [
            Hypothesis("h0", {"x": "0"}, "safe"),
            Hypothesis("h1", {"x": "1"}, "unsafe"),
        ],
        [Observation("x", 2.0)],
    )
    state = replay(p, Trace.from_pairs([("x", "0")]))
    assert state.evidence == {"x": "0"}
    assert state.compatible == frozenset({"h0"})
    assert state.cost.execution == 2.0


def test_replay_rejects_duplicate_steps():
    p = FiniteProblem(
        [Hypothesis("h0", {"x": "0"}, "safe")],
        [Observation("x", 1.0)],
    )
    try:
        replay(p, Trace.from_pairs([("x", "0"), ("x", "0")]))
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate observations must fail replay")


def test_exact_solver_chooses_cheapest_decisive_observation():
    p = FiniteProblem(
        [
            Hypothesis("h0", {"cheap": "0", "expensive": "0"}, "safe"),
            Hypothesis("h1", {"cheap": "1", "expensive": "1"}, "unsafe"),
        ],
        [Observation("cheap", 1.0), Observation("expensive", 4.0)],
    )
    result = solve_expected(p)
    assert result.expected_cost == 1.0
    assert result.policy is not None
    assert result.policy.observation_id == "cheap"


def test_exact_solver_allows_non_identification():
    p = FiniteProblem(
        [
            Hypothesis("h0", {"x": "0"}, "safe"),
            Hypothesis("h1", {"x": "0"}, "safe"),
        ],
        [Observation("x", 1.0)],
    )
    result = solve_expected(p)
    assert result.expected_cost == 0.0
    assert result.policy is None
