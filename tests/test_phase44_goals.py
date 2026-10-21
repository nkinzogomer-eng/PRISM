"""Phase 4.4 goal-first, label-blind candidate and quality-gate tests.

These are transparent developer fixtures, not an independent evaluation set.
A candidate does not count as a confirmed vulnerability.
"""
from __future__ import annotations

import unittest

from prism.goal_discovery import DiscoveryGoal, analyze, summarize_goal


def check(code: str) -> dict:
    return analyze(code, "fixture.py").as_record()


class ObjectiveContractTests(unittest.TestCase):
    def test_goal_safeguards(self):
        with self.assertRaises(ValueError):
            DiscoveryGoal(property_id="CWE-89")
        with self.assertRaises(ValueError):
            DiscoveryGoal(target_recall=1.4)
        with self.assertRaises(ValueError):
            DiscoveryGoal(max_seconds_per_case=0)
        goal = DiscoveryGoal()
        self.assertTrue(goal.require_independent_confirmation)

    def test_source_to_open_candidate_not_confirmed(self):
        d = check('''
def route():
    name = request.cookies.get("name")
    file_name = f"/srv/private/{name}"
    return open(file_name, "rb").read()
''')
        self.assertEqual(d["candidate_count"], 1)
        self.assertEqual(d["verified_count"], 0)
        self.assertEqual(d["findings"][0]["status"], "candidate")
        self.assertEqual(d["findings"][0]["sink"], "open")
        self.assertEqual(d["findings"][0]["line"], 5)
        self.assertIn("request.cookies.get", d["findings"][0]["sources"][0])

    def test_no_source_no_candidate(self):
        d = check('''
def route():
    path = "/srv/public/info.txt"
    return open(path).read()
''')
        self.assertEqual(d["candidate_count"], 0)
        self.assertEqual(d["verified_count"], 0)

    def test_decision_eliminates_unreachable_source(self):
        d = check('''
def route():
    user = request.args.get("f")
    num = 106
    filename = "constant.txt" if 7*18 + num > 200 else user
    return open(filename).read()
''')
        self.assertEqual(d["candidate_count"], 0)

    def test_alternative_branch_definitely_propagates(self):
        d = check('''
def route():
    user = request.cookies.get("f")
    bar = "This should never happen"
    if "should" in bar:
        bar = user
    return open(bar, "r")
''')
        self.assertEqual(d["candidate_count"], 1)

    def test_optional_user_input_branch_creates_candidate_not_proof(self):
        d = check('''
def route():
    supplied = request.form.get("filename")
    if not supplied:
        supplied = ""
    return open("/testfiles/" + supplied)
''')
        self.assertEqual(d["candidate_count"], 1)
        self.assertEqual(d["verified_count"], 0)
        self.assertIn("unknown_branch", d["findings"][0]["uncertainties"])

    def test_unknown_external_helper_not_promoted_to_high_confidence(self):
        d = check('''
def route():
    user = request.cookies.get("f")
    p = SomeFactory.create().transform(user)
    return open(p)
''')
        self.assertEqual(d["candidate_count"], 0)
        self.assertEqual(d["unknown_count"], 1)
        self.assertEqual(d["findings"][0]["status"], "unknown")
        self.assertIn("unmodeled_transform", " ".join(d["findings"][0]["uncertainties"]))

    def test_conditional_filesystem_sink_is_not_missed(self):
        d = check('''
def route():
    from pathlib import Path
    supplied = request.cookies.get("filename")
    p = Path("/tmp/staging") / supplied
    if p.exists():
        return "present"
    return "not present"
''')
        self.assertEqual(d["candidate_count"], 1)
        self.assertEqual(d["findings"][0]["sink"], "p.exists")

    def test_known_local_helper_is_followed(self):
        d = check('''
def identity(x):
    return x
def route():
    user = request.form.get("filename")
    p = identity(user)
    return open(p)
''')
        self.assertEqual(d["candidate_count"], 1)

    def test_precise_literal_dictionary_key_propagation(self):
        d = check('''
def route():
    supplied = request.form.get("filename")
    mapping = {}
    mapping["public"] = "safe"
    mapping["requested"] = supplied
    selected = mapping["requested"]
    return open(selected)
''')
        self.assertEqual(d["candidate_count"], 1)
        self.assertEqual(d["unknown_count"], 0)

    def test_dictionary_safe_key_is_not_tainted_by_another_value(self):
        d = check('''
def route():
    supplied = request.form.get("filename")
    mapping = {"a": supplied, "b": "/safe/file.txt"}
    return open(mapping["b"])
''')
        self.assertEqual(d["candidate_count"], 0)

    def test_configparser_explicit_write_read_flow(self):
        d = check('''
def route():
    supplied = request.form.get("filename")
    conf = configparser.ConfigParser()
    conf.set("section", "key", supplied)
    filename = conf.get("section", "key")
    return open(filename)
''')
        self.assertEqual(d["candidate_count"], 1)

    def test_request_wrapper_as_opaque_but_declared_entry_point(self):
        d = check('''
def route():
    wrapper = helpers.separate_request.request_wrapper(request)
    supplied = wrapper.get_form_parameter("name")
    return open(supplied)
''')
        self.assertEqual(d["candidate_count"], 1)

    def test_information_disclosure_sink(self):
        d = check('''
def route():
    user = request.cookies.get("file")
    from pathlib import Path
    p = Path("/safe") / user
    return p.exists()
''')
        self.assertEqual(d["candidate_count"], 1)
        self.assertEqual(d["findings"][0]["sink"], "p.exists")

    def test_guards_remain_unknown_until_verified(self):
        d = check('''
def route():
    user = request.cookies.get("f")
    if "../" in user:
        return "invalid"
    return open(user).read()
''')
        self.assertEqual(d["candidate_count"], 0)
        self.assertEqual(d["unknown_count"], 1)
        self.assertIn("unproven_path_guard", " ".join(d["findings"][0]["uncertainties"]))

    def test_literal_dictionary_key_is_now_precisely_tracked(self):
        d = check('''
def route():
    user = request.args.get("f")
    values = {"some": "safe", "f": user}
    return open(values["f"])
''')
        self.assertEqual(d["candidate_count"], 1)
        self.assertEqual(d["unknown_count"], 0)
        self.assertEqual(d["verified_count"], 0)

    def test_syntax_errors_unknown_never_negative(self):
        d = check("def broken(:\n  return open(request.cookies.get('name'))\n")
        self.assertTrue(d["unresolved"])
        self.assertEqual(d["verified_count"], 0)

    def test_benchmark_label_matches_are_not_verified_finds(self):
        pos = check('''
def attack():
    param = request.cookies.get("x")
    open(param)
''')
        neg = check('''
def safe():
    open("/fixed/path")
''')
        metrics = summarize_goal({"p": True, "n": False},
                                 {"p": pos, "n": neg}, DiscoveryGoal())
        self.assertEqual(metrics["tp_against_labels"], 1)
        self.assertEqual(metrics["tn_against_labels"], 1)
        self.assertEqual(metrics["verified_vulnerabilities"], 0)
        self.assertFalse(metrics["verified_target_met"])

    def test_unknown_label_case_not_counted_as_negative(self):
        ambiguous = check('''
def case():
    val = request.args.get("x")
    return open(foo(val))
''')
        metric = summarize_goal({"p": True}, {"p": ambiguous}, DiscoveryGoal())
        self.assertEqual(metric["unknown"], 1)
        self.assertEqual(metric["fn_against_labels"], 0)


if __name__ == "__main__":
    unittest.main()
