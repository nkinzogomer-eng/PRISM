import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from prism.evaluation import CostVector
from prism.reference import Cost, FiniteProblem, Hypothesis, Observation


class CostValidationTests(unittest.TestCase):
    def problem(self, cost=1.0):
        return FiniteProblem(
            [Hypothesis("h0", {"a": "0"}, "safe")],
            [Observation("a", cost)],
        )

    def test_observation_rejects_each_invalid_cost(self):
        for value in (-1, float("nan"), float("inf"), float("-inf"), "1", True, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.problem(value)

    def test_cost_rejects_each_invalid_component(self):
        for component in Cost.COMPONENTS:
            for value in (-1, float("nan"), float("inf"), float("-inf"), "1", True, [], {}):
                with self.subTest(component=component, value=value):
                    with self.assertRaises(ValueError):
                        Cost(**{component: value})

    def test_cost_add_rejects_invalid_delta_and_unknown_component(self):
        cost = Cost()
        for value in (-1, float("nan"), float("inf"), float("-inf"), "1", True, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    cost.add(execution=value)
        with self.assertRaises(ValueError):
            cost.add(memory=1.0)

    def test_cost_vector_rejects_bool_and_non_numeric_values(self):
        for value in (True, "1", float("nan"), float("inf"), -1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    CostVector(planning=value, execution=0.0)

    def test_cli_rejects_invalid_cost_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "problem.json"
            path.write_text(
                json.dumps({
                    "hypotheses": [{"id": "h0", "observations": {"a": "0"}, "decision": "safe"}],
                    "observations": [{"id": "a", "cost": "1"}],
                }),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [sys.executable, "-m", "prism", "run", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(json.loads(completed.stdout)["status"], "ERROR")
            self.assertNotIn("Traceback", completed.stderr)


if __name__ == "__main__":
    unittest.main()
