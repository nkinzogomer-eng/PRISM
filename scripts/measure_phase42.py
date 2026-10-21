"""Fresh Bandit experiment; never substitutes archived output for scanner time."""
import argparse
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
try:
    from .phase42_structure import select
    from .phase4_evidence import validate_scan
    from .score_phase4 import read_labels, calculate
except ImportError:
    from phase42_structure import select
    from phase4_evidence import validate_scan
    from score_phase4 import read_labels, calculate


def identity(item):
    return (Path(item['filename']).name, item['test_id'], item['line_number'],
            item.get('col_offset'), item['issue_text'])


def measure(source_dir, labels_path, output, repeats=3):
    if repeats < 1:
        raise ValueError('repeats must be positive')
    output.mkdir(parents=True, exist_ok=True)
    report = {'mode': 'fresh scanner execution', 'development_only': True,
              'python': sys.version, 'platform': platform.platform(),
              'scanner': subprocess.check_output([sys.executable, '-m', 'bandit', '--version'],
                                                text=True).strip(),
              'missing_costs': ['installation/network (performed separately)',
                               'CPU', 'peak memory', 'agent billing/tokens'],
              'runs': []}
    # Rotated order limits, but does not eliminate, warm-cache/order effects.
    policies = ['full', 'simple', 'prism']
    for repeat in range(repeats):
        baselines = {}
        rows = []
        for policy in policies[repeat % 3:] + policies[:repeat % 3]:
            total = time.perf_counter()
            start = total
            sources = {p.name: p.read_bytes() for p in sorted(source_dir.glob('BenchmarkTest*.py'))}
            if not sources:
                raise ValueError('empty development corpus')
            digest = hashlib.sha256()
            for name, raw in sources.items():
                digest.update(name.encode() + b'\0' + raw)
            preparation = time.perf_counter() - start
            start = time.perf_counter()
            selected, reasons = [], Counter()
            for name, raw in sources.items():
                chosen, graph = select(raw.decode('utf-8-sig'), policy)
                if chosen:
                    selected.append(name)
                if graph:
                    reasons.update(graph['uncertainty'])
            selection = time.perf_counter() - start
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                start = time.perf_counter()
                for name in selected:
                    (root / name).write_bytes(sources[name])
                staging = time.perf_counter() - start
                raw_path = output / f'{repeat}-{policy}-raw.json'
                start = time.perf_counter()
                command = [sys.executable, '-m', 'bandit', '-r', str(root), '-f', 'json', '-q']
                with raw_path.open('w', encoding='utf-8') as handle:
                    proc = subprocess.run(command, stdout=handle, stderr=subprocess.PIPE,
                                          text=True, timeout=120)
                analysis = time.perf_counter() - start
                start = time.perf_counter()
                data = json.loads(raw_path.read_text(encoding='utf-8'))
                problems = validate_scan('bandit', proc.returncode, data)
                scanned = {Path(p).name for p in data.get('metrics', {})}
                if not set(selected).issubset(scanned):
                    problems.append('missing_modules')
                if problems:
                    raise ValueError(problems)
                ledger = sorted(identity(item) for item in data['results'])
                baselines[policy] = set(ledger)
                # Labels enter only here, after selection and scanner execution.
                labels = read_labels(labels_path)
                if set(labels) != {Path(n).stem for n in sources}:
                    raise ValueError('source/label inventory mismatch')
                flagged = {Path(item[0]).stem for item in ledger}
                predictions = {key: ('ok', key in flagged) if key + '.py' in selected
                               else ('skipped', None) for key in labels}
                score = calculate(labels, predictions)['results']
                verification = time.perf_counter() - start
            row = {'repeat': repeat, 'policy': policy, 'selected': len(selected),
                   'total_files': len(sources), 'source_manifest_sha256': digest.hexdigest(),
                   'uncertainty': dict(reasons), 'findings': ledger, 'quality': score,
                   'seconds': {'preparation': preparation, 'selection': selection,
                               'staging': staging, 'analysis': analysis,
                               'verification': verification,
                               'total_through_cleanup': time.perf_counter() - total}}
            rows.append(row)
        for row in rows:
            row['lost_findings_vs_full'] = sorted(baselines['full'] - baselines[row['policy']])
            row['extra_findings_vs_full'] = sorted(baselines[row['policy']] - baselines['full'])
        report['runs'].extend(rows)
    report['serialization_in_total'] = False
    (output / 'measurement.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    measure(args.source_dir, args.labels, args.output, args.repeats)
