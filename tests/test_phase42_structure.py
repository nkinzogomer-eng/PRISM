import unittest
from scripts.phase42_structure import dependency_graph, select
from scripts.measure_phase42 import identity, measure


class StructureTests(unittest.TestCase):
    def test_finding_identity_retains_rule_and_location(self):
        item = dict(filename='/temp/a.py', test_id='B608', line_number=4,
                    col_offset=2, issue_text='sql')
        self.assertEqual(identity(item), ('a.py', 'B608', 4, 2, 'sql'))
        with self.assertRaises(ValueError):
            measure(None, None, None, repeats=0)

    def test_dependencies_include_later_and_branch_definitions(self):
        g = dependency_graph('x = source\nif flag:\n x = other\nsink(x)\nx = later\n')
        self.assertIn((4, 1, 'may_read'), g['edges'])
        self.assertIn((4, 5, 'may_read'), g['edges'])
        self.assertIn((3, 2, 'lexical_control'), g['edges'])
        self.assertFalse(g['certifies_safety'])

    def test_unknowns_always_scan(self):
        for source in ['bad(', 'from os import open as f\nf(user)',
                       'obj[key] = user', 'getattr(db, name)(query)',
                       'def wrapper(x):\n return helper(x)',
                       'import pathlib\np = pathlib.Path(root) / user',
                       'query = "SELECT " + user', 'x = 1']:
            with self.subTest(source=source):
                self.assertTrue(select(source, 'prism')[0])

    def test_simple_alias_counterexample(self):
        source = 'from os import system as run\nrun(user)'
        self.assertFalse(select(source, 'simple')[0])
        self.assertTrue(select(source, 'prism')[0])

    def test_only_inert_grammar_excluded(self):
        for source in ['', '# comment', '"documentation"\npass\n42']:
            chosen, graph = select(source, 'prism')
            self.assertFalse(chosen)
            self.assertFalse(graph['certifies_safety'])
