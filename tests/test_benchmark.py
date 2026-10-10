from prism.generators import misspecified, parity, sparse_binary
from prism.policies import decision_disagreement, fixed_cost, random_order


def test_sparse_generator_is_reproducible():
    a = sparse_binary(seed=7, n=4, support=2)
    b = sparse_binary(seed=7, n=4, support=2)
    assert a.hidden_id == b.hidden_id
    assert a.problem.observations == b.problem.observations
    assert a.problem.hypotheses == b.problem.hypotheses


def test_misspecified_hidden_world_is_not_declared():
    generated = misspecified(seed=3)
    assert generated.hidden_id not in generated.declared_ids
    assert generated.hidden_id not in generated.problem.hypotheses


def test_parity_keeps_all_variables_available():
    generated = parity(n=4)
    assert set(generated.problem.observations) == {"x0", "x1", "x2", "x3"}
    assert len(generated.problem.hypotheses) == 16


def test_policies_are_sound_or_abstain():
    generated = sparse_binary(seed=2, n=4, support=2)
    for policy in (fixed_cost, random_order, decision_disagreement):
        run = policy(generated.problem, generated.hidden_id)
        assert run.result.status in {"CERTIFIED_DECISION", "ABSTAIN"}
        if run.result.status == "CERTIFIED_DECISION":
            assert generated.problem.verify(run.result.certificate)
