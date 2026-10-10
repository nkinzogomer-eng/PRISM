from prism.reference import (
    FiniteProblem, Hypothesis, Observation, abstain, certified_stop,
)


def problem():
    return FiniteProblem(
        hypotheses=[
            Hypothesis("h00", {"a": "0", "b": "0"}, "right"),
            Hypothesis("h01", {"a": "0", "b": "1"}, "right"),
            Hypothesis("h10", {"a": "1", "b": "0"}, "left"),
            Hypothesis("h11", {"a": "1", "b": "1"}, "left"),
        ],
        observations=[Observation("a", 1.0), Observation("b", 2.0)],
    )


def test_initial_state_is_not_sufficient():
    p = problem()
    assert certified_stop(p, p.initial_state()) is None


def test_decision_sufficiency_does_not_require_model_identification():
    p = problem()
    state = p.apply(p.initial_state(), "a", "0")
    result = certified_stop(p, state)
    assert result is not None
    assert result.status == "CERTIFIED_DECISION"
    assert result.decision == "right"
    assert set(result.certificate.hypothesis_ids) == {"h00", "h01"}
    assert p.verify(result.certificate)


def test_certificate_rejects_wrong_decision():
    p = problem()
    state = p.apply(p.initial_state(), "a", "0")
    certificate = p.certificate(state)
    assert certificate is not None
    invalid = certificate.__class__(certificate.hypothesis_ids, certificate.evidence, "left")
    assert not p.verify(invalid)


def test_evidence_can_reduce_to_one_model():
    p = problem()
    state = p.apply(p.initial_state(), "a", "0")
    state = p.apply(state, "b", "0")
    assert state.compatible == frozenset({"h00"})
    result = certified_stop(p, state)
    assert result is not None
    assert result.decision == "right"


def test_abstention_is_explicit():
    p = problem()
    result = abstain(p, p.initial_state(), "budget_exhausted")
    assert result.status == "ABSTAIN"
    assert result.decision is None
    assert result.reason == "budget_exhausted"


def test_unknown_observation_is_rejected():
    p = problem()
    try:
        p.apply(p.initial_state(), "unknown", "0")
    except KeyError:
        pass
    else:
        raise AssertionError("unknown observations must be rejected")
