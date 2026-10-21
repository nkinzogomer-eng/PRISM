"""Replay archived Phase 4 findings; labels are used only in offline scoring."""
import argparse
import csv
import hashlib
import json
import time
from collections import Counter
from pathlib import Path
try:
    from .phase4_evidence import case_from_uri, cwes, decision_context
    from .score_phase4 import read_labels, calculate
except ImportError:
    from phase4_evidence import case_from_uri, cwes, decision_context
    from score_phase4 import read_labels, calculate


def findings(tool, data):
    if tool.startswith('codeql'):
        for run in data['runs']:
            artifacts = run.get('artifacts', [])
            for item in run.get('results', []):
                component = item.get('rule', {}).get('toolComponent', {})
                driver = run['tool']['driver']
                if 'index' in component:
                    driver = run['tool'].get('extensions', [])[component['index']]
                rules = {r['id']: r for r in driver.get('rules', [])}
                rule = rules.get(item.get('ruleId'), {})
                tags = rule.get('properties', {}).get('tags', [])
                for loc in item.get('locations', []):
                    physical = loc.get('physicalLocation', {})
                    artifact = physical.get('artifactLocation', {})
                    uri = artifact.get('uri')
                    if uri is None and 'index' in artifact:
                        uri = artifacts[artifact['index']]['location']['uri']
                    yield item.get('ruleId'), uri or '', physical.get('region', {}).get('startLine'), cwes([t for t in tags if 'cwe' in t.lower()])
    else:
        for item in data['results']:
            if tool == 'bandit':
                yield item['test_id'], item['filename'], item.get('line_number'), cwes(item.get('issue_cwe', {}).get('id', []))
            else:
                yield item['check_id'], item['path'], item.get('start', {}).get('line'), cwes(item.get('extra', {}).get('metadata', {}).get('cwe', []))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--input', action='append', required=True, help='tool=raw JSON/SARIF')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    started = time.perf_counter()
    labels = read_labels(args.labels)
    with args.labels.open(encoding='utf-8-sig') as handle:
        expected_cwe = {r[0]: int(r[3]) for r in csv.reader(handle) if r and not r[0].startswith('#')}
    source_digest = hashlib.sha256()
    for path in sorted(args.source_dir.glob('BenchmarkTest*.py')):
        source_digest.update(path.name.encode() + b'\0' + path.read_bytes())
    report = {'development_only': True,
        'label_sha256': hashlib.sha256(args.labels.read_bytes()).hexdigest(),
        'source_manifest_sha256': source_digest.hexdigest(), 'tools': {}, 'costs': {
        'mode': 'archived replay; scanner execution not repeated',
        'monetary_cost': None, 'agent_tokens_and_compute': 'not exposed; not zero',
        'missing': ['fresh scanner timings', 'peak memory', 'setup/network costs', 'agent billing']}}
    ledger = []
    decisions = {}
    for spec in args.input:
        tool, filename = spec.split('=', 1)
        raw = Path(filename).read_bytes()
        data = json.loads(raw)
        coarse, relevant = set(), set()
        counts = Counter()
        context_seconds = 0
        for rule, uri, line, observed in findings(tool, data):
            case = case_from_uri(uri)
            if case not in labels:
                counts['unmapped'] += 1
                continue
            coarse.add(case)
            match = expected_cwe[case] in observed
            if match:
                relevant.add(case)
            counts['cwe_match' if match else 'cwe_mismatch_or_missing'] += 1
            source = args.source_dir / (case + '.py')
            before = time.perf_counter()
            context = None
            valid_line = False
            if source.exists() and isinstance(line, int):
                text = source.read_text(encoding='utf-8-sig')
                valid_line = 1 <= line <= len(text.splitlines())
                if valid_line:
                    context = decision_context(text, line)
            context_seconds += time.perf_counter() - before
            counts['valid_line' if valid_line else 'invalid_or_missing_line'] += 1
            ledger.append({'tool': tool, 'case': case, 'rule': rule, 'line': line,
                           'expected_cwe': expected_cwe[case], 'alert_cwes': sorted(observed),
                           'cwe_match': match, 'expected_positive': labels[case][1],
                           'location_valid': valid_line, 'context': context})
        metrics = {}
        for name, ids in [('any_finding', coarse), ('exact_cwe_metadata', relevant)]:
            metrics[name] = calculate(labels, {k: ('ok', k in ids) for k in labels})['results']
        report['tools'][tool] = {'sha256': hashlib.sha256(raw).hexdigest(),
                                 'counts': dict(counts), 'metrics': metrics,
                                 'context_seconds_including_source_io': context_seconds}
        if tool.startswith('codeql'):
            extracted = set()
            successful = True
            for run in data['runs']:
                for invocation in run.get('invocations', []):
                    successful &= invocation.get('executionSuccessful') is True
                    for n in invocation.get('toolExecutionNotifications', []):
                        if n.get('descriptor', {}).get('id') == 'py/diagnostics/successfully-extracted-files':
                            extracted.update(case_from_uri(l.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')) for l in n.get('locations', []))
            report['tools'][tool]['extraction'] = {'successful': successful,
                'labeled_modules': len(extracted & labels.keys()), 'missing': sorted(labels.keys() - extracted)}
        decisions[tool] = coarse
    report['fixed_combinations'] = {}
    for name, tools in [('bandit_semgrep_or', ['bandit', 'semgrep']),
                        ('all_tools_or', list(decisions))]:
        if all(t in decisions for t in tools):
            ids = set().union(*(decisions[t] for t in tools))
            report['fixed_combinations'][name] = calculate(labels, {k: ('ok', k in ids) for k in labels})['results']
    report['structural_ablation'] = {
        'decisions_changed': 0, 'purpose': 'explanation context only; detector decisions preserved',
        'scope_statements': sum(x['context']['scope_statements'] for x in ledger if x['context']),
        'selected_statements': sum(x['context']['selected_statements'] for x in ledger if x['context'])}
    report['costs']['replay_seconds_before_serialization'] = time.perf_counter() - started
    report['limitations'] = ['Exact CWE metadata is an ablation, not semantic adjudication.',
        'Valid source line does not establish intended sink relevance.',
        'AST context does not resolve imports, calls, aliases, branches or sanitizers.',
        'No findings are suppressed by the structural prototype; no independent evaluation performed.']
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'audit.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    (args.output / 'findings.json').write_text(json.dumps(ledger, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
