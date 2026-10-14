import unittest

from prism.evaluation import CostVector, score_run, summarize_policy
from prism.generators import sparse_binary
from prism.policies import fixed_cost
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

    def test_policy_summary_reports_cold_start_amortized_and_tail(self):
        generated = sparse_binary(seed=2, n=3, support=1)
        outcome = run_order(generated, fixed_cost(generated))
        records = []
        for run_id, planning in (("cold", 4.0), ("repeat", 2.0)):
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
        self.assertEqual(summary.costs.cold_start.planning, 4.0)
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
