import unittest

from prism.benchmark import run_policy_suite
from prism.evaluation import (
    CostVector,
    evaluate_order_policy,
    score_run,
    summarize_policy,
)
from prism.generators import Generated, misspecified, sparse_binary
from prism.policies import fixed_cost, random_order
from prism.reference import FiniteProblem, Hypothesis, Observation
from prism.runner import run_order


class EvaluationTests(unittest.TestCase):
    def test_scores_completed_decision_and_cost_components(self):
        generated = sparse_binary(seed=2, n=3, support=1)
        outcome = run_order(generated, fixed_cost(generated))
        metrics = score_run(
            generated,
            outcome,
            policy="fixed_cost",
            run_id="seed-2",
            costs=CostVector(
                planning=0.25,
                execution=outcome.execution_cost,
                verification=0.01,
                representation=0.0,
                preprocessing=0.0,
            ),
        )
        self.assertEqual(metrics.status, "CERTIFIED_DECISION")
        self.assertTrue(metrics.correct_decision)
        self.assertFalse(metrics.incorrect_non_abstention)
        self.assertEqual(metrics.costs.planning, 0.25)
        self.assertEqual(metrics.costs.execution, outcome.execution_cost)
        self.assertEqual(metrics.costs.verification, outcome.verification_time_seconds)
        self.assertIsNone(metrics.costs.memory)

    def test_execution_cost_comes_from_completed_runner(self):
        generated = sparse_binary(seed=2, n=3, support=1)
        outcome = run_order(generated, fixed_cost(generated))
        metrics = score_run(
            generated,
            outcome,
            policy="fixed_cost",
            run_id="seed-2",
            costs=CostVector(planning=0.25, execution=0.0),
        )
        self.assertEqual(metrics.costs.execution, outcome.execution_cost)

    def test_policy_planning_is_measured_without_hidden_world_access(self):
        generated = sparse_binary(seed=2, n=3, support=1)
        seen = []

        def policy(public_view):
            seen.append((public_view.world_table, public_view.hidden_id))
            return fixed_cost(public_view)

        metrics = evaluate_order_policy(
            generated, policy, policy="fixed_cost", run_id="seed-2"
        )
        self.assertEqual(seen, [({}, "")])
        self.assertGreaterEqual(metrics.costs.planning, 0.0)
        self.assertGreaterEqual(metrics.costs.verification, 0.0)
        self.assertGreater(metrics.costs.execution, 0.0)
        self.assertIsNone(metrics.costs.representation)

    def test_policy_mutation_cannot_change_evaluator_or_next_policy(self):
        generated = sparse_binary(seed=2, n=3, support=1)
        expected = evaluate_order_policy(
            generated, fixed_cost, policy="baseline", run_id="baseline"
        )
        original_hypotheses = list(generated.declared.hypotheses)
        original_observations = list(generated.declared.observations)

        def mutating_policy(public_view):
            order = fixed_cost(public_view)
            public_view.declared.hypotheses.clear()
            public_view.declared.observations.clear()
            return order

        mutated = evaluate_order_policy(
            generated, mutating_policy, policy="mutator", run_id="mutated"
        )
        after_mutator = evaluate_order_policy(
            generated, fixed_cost, policy="after-mutator", run_id="after"
        )

        self.assertEqual(generated.declared.hypotheses, original_hypotheses)
        self.assertEqual(generated.declared.observations, original_observations)
        self.assertEqual(mutated.status, expected.status)
        self.assertEqual(mutated.decision, expected.decision)
        self.assertEqual(after_mutator.status, expected.status)
        self.assertEqual(after_mutator.decision, expected.decision)

    def test_evaluator_marks_contradiction_as_correct_abstention(self):
        declared = FiniteProblem(
            hypotheses=[
                Hypothesis("left", {"a": "seen", "b": "left"}, "left"),
                Hypothesis("right", {"a": "seen", "b": "right"}, "right"),
            ],
            observations=[Observation("a", 1.0), Observation("b", 1.0)],
        )
        generated = Generated(
            declared=declared,
            world_table={"outside": {
                "observations": {"a": "seen", "b": "other"},
                "decision": "outside",
            }},
            hidden_id="outside",
        )
        metrics = evaluate_order_policy(
            generated,
            lambda public_view: ["a", "b"],
            policy="contradiction",
            run_id="outside",
        )
        self.assertEqual(metrics.status, "ABSTAIN")
        self.assertTrue(metrics.correct_abstention)
        self.assertFalse(metrics.incorrect_non_abstention)

    def test_evaluator_counts_wrong_certificates_on_omitted_worlds(self):
        incorrect = []
        for seed in range(50):
            generated = misspecified(seed=seed, n=3, support=2)
            metrics = evaluate_order_policy(
                generated,
                fixed_cost,
                policy="fixed_cost",
                run_id=str(seed),
            )
            if metrics.incorrect_non_abstention:
                incorrect.append(metrics)

        self.assertTrue(incorrect)
        self.assertTrue(all(
            metric.status == "CERTIFIED_DECISION"
            and metric.correct_decision is False
            for metric in incorrect
        ))

    def test_policy_suite_compares_policies_on_shared_instances(self):
        instances = [
            (f"seed-{seed}", sparse_binary(seed=seed, n=3, support=1))
            for seed in range(3)
        ]
        summaries = run_policy_suite(
            instances,
            {
                "fixed_cost": fixed_cost,
                "random": lambda public_view: random_order(public_view, seed=9),
            },
        )
        self.assertEqual(set(summaries), {"fixed_cost", "random"})
        for summary in summaries.values():
            self.assertEqual(summary.runs, len(instances))
            self.assertEqual(summary.certified_decision_rate, 1.0)
            self.assertGreaterEqual(summary.costs.amortized.planning, 0.0)

    def test_policy_summary_reports_first_run_amortized_and_tail(self):
        generated = sparse_binary(seed=2, n=3, support=1)
        outcome = run_order(generated, fixed_cost(generated))
        records = []
        for run_id, planning in (("first", 4.0), ("repeat", 2.0)):
            records.append(score_run(
                generated,
                outcome,
                policy="measured",
                run_id=run_id,
                costs=CostVector(
                    planning=planning,
                    execution=outcome.execution_cost,
                    verification=1.0,
                ),
            ))
        summary = summarize_policy(records)
        self.assertEqual(summary.runs, 2)
        self.assertEqual(summary.certified_decision_rate, 1.0)
        self.assertEqual(summary.incorrect_non_abstention_rate, 0.0)
        self.assertEqual(summary.costs.first_run.planning, 4.0)
        self.assertEqual(summary.costs.amortized.planning, 3.0)
        self.assertEqual(summary.costs.tail.planning, 4.0)
        self.assertIsNone(summary.costs.amortized.representation)

    def test_scalarization_requires_explicit_complete_weights(self):
        costs = CostVector(
            planning=1.0,
            execution=2.0,
            verification=3.0,
            representation=4.0,
            preprocessing=5.0,
            memory=6.0,
            communication=7.0,
        )
        weights = {name: 1.0 for name in CostVector.COMPONENTS}
        self.assertEqual(costs.weighted_total(weights), 28.0)
        with self.assertRaises(ValueError):
            costs.weighted_total({"planning": 1.0})

    def test_unmeasured_component_cannot_be_scalarized_as_zero(self):
        costs = CostVector(planning=1.0, execution=2.0)
        weights = {name: 1.0 for name in CostVector.COMPONENTS}
        with self.assertRaises(ValueError):
            costs.weighted_total(weights)

    def test_negative_cost_is_rejected(self):
        with self.assertRaises(ValueError):
            CostVector(planning=-1.0, execution=2.0)


if __name__ == "__main__":
    unittest.main()
