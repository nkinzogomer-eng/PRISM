"""Narrow, auditable rule-specific reuse certificates for Bandit B307.

This experiment targets Bandit 1.8.6 B307 (insecure eval call).
The only *proven-by-construction* shortcut here is an exact source-prefix
extension by a single prescribed standalone inert marker comment.
This establishes unchanged existing code bytes/AST locations under a
successful prior parse; it is NOT a proof that arbitrary Bandit plugins or
all future analyzers are insensitive to append-only comments.

No certificates claim a file is safe; they only allow reuse of cached
B307 alerts under this expressly bounded source transformation contract.
"""
from __future__ import annotations

import ast
import hashlib
import io
import re
import tokenize
from dataclasses import dataclass


MARKER = re.compile(rb"\# SCM43C-INERT-[0-9]{1,5}\n\Z", re.ASCII)
# Deliberately check scanner control comments, not just AST equivalence.
NOSEC = re.compile(r"\b(?:nosec|noqa|semgrep|bandit|pragma|skip)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Decision:
    reusable: bool
    reason: str


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def suffix_certificate(previous: bytes, candidate: bytes) -> Decision:
    """Constant-scope exact-prefix proof of a *prescribed* no-op source edit.

    For a prior successfully parsed Python source ending with newline, adding
    exactly one standalone inert marker comment leaves every existing byte and
    source location fixed. Parser-success premise is checked in our benchmark
    and inherited from the known successful baseline scan otherwise.
    """
    if not previous.endswith(b"\n"):
        return Decision(False, "old_source_has_no_terminal_newline")
    if not candidate.startswith(previous):
        return Decision(False, "old_source_not_exact_prefix")
    tail = candidate[len(previous):]
    if not MARKER.fullmatch(tail):
        return Decision(False, "extension_not_allowlisted_inert_comment")
    return Decision(True, "exact_prefix_and_single_inert_comment")


def conventional_suffix_diff(previous: bytes, candidate: bytes) -> Decision:
    """Ordinary independently-coded byte-prefix diff comparator.

    Uses exactly the same preconditions and rule-restricted edit family as the
    SCM-labelled certificate, but has no SCM planning or graph machinery.
    A comparable result falsifies any claim of a distinctive SCM speedup.
    """
    size = len(previous)
    if not previous.endswith(b"\n"):
        return Decision(False, "diff_no_previous_newline")
    if len(candidate) < size or candidate[:size] != previous:
        return Decision(False, "diff_original_prefix_modified")
    if MARKER.fullmatch(candidate[size:]) is None:
        return Decision(False, "diff_not_prescribed_comment")
    return Decision(True, "conventional_prefix_diff_certificate")


def _nosec_fingerprint(raw: bytes) -> tuple:
    """Extract all lines with scanner-sensitive comment control words."""
    candidates = []
    try:
        for tok in tokenize.tokenize(io.BytesIO(raw).readline):
            if tok.type == tokenize.COMMENT and NOSEC.search(tok.string):
                candidates.append((tok.start, tok.string))
    except (SyntaxError, UnicodeError, tokenize.TokenError, IndentationError):
        raise ValueError("tokenization not trustworthy")
    return tuple(candidates)


def ast_reference_certificate(previous: bytes, candidate: bytes) -> Decision:
    """Stronger *conventional* AST+directive equivalence baseline.

    This is a conservative empirical comparator, NOT a formal proof of arbitrary
    scanner behavior. AST dumps include all positions to preserve rule locations.
    Scanner directive comments are byte/line anchored; a change invalidates.
    """
    if previous == candidate:
        return Decision(True, "identical_bytes")
    try:
        a = ast.dump(ast.parse(previous), include_attributes=True)
        b = ast.dump(ast.parse(candidate), include_attributes=True)
        directives_same = _nosec_fingerprint(previous) == _nosec_fingerprint(candidate)
    except (SyntaxError, ValueError, RecursionError, TypeError):
        return Decision(False, "parser_or_tokenizer_uncertain")
    if not directives_same:
        return Decision(False, "scanner_directives_changed")
    if a != b:
        return Decision(False, "ast_or_positions_changed")
    return Decision(True, "ast_and_directive_signature_match")


def select_reanalysis(mode: str, before: dict[str, bytes],
                      after: dict[str, bytes]) -> tuple[set[str], dict[str, int]]:
    """Every unknown or changed-source non-certified module is reanalyzed."""
    if mode not in {"full", "hash", "ast_reference", "diff_reference", "scm_suffix"}:
        raise ValueError("invalid mode")
    if not set(after) <= set(before):
        raise ValueError("new modules require separate cache-entry bootstrapping")
    selected = set()
    reasons: dict[str, int] = {}
    for name, raw in after.items():
        original = before[name]
        if mode == "full":
            result = Decision(False, "full")
        elif original == raw:
            result = Decision(True, "same_hash")
        elif mode == "hash":
            result = Decision(False, "changed_bytes")
        elif mode == "ast_reference":
            result = ast_reference_certificate(original, raw)
        elif mode == "diff_reference":
            result = conventional_suffix_diff(original, raw)
        else:
            result = suffix_certificate(original, raw)
        reasons[result.reason] = reasons.get(result.reason, 0) + 1
        if not result.reusable:
            selected.add(name)
    return selected, reasons


def merge_or_fail(universe: set[str], selected: set[str],
                  prior: dict[str, tuple[tuple, ...]],
                  fresh: dict[str, tuple[tuple, ...]]) -> dict[str, tuple[tuple, ...]]:
    if set(prior) != universe or not selected <= universe or set(fresh) != selected:
        raise ValueError("partial cache or scanner inventory")
    return {name: (fresh[name] if name in selected else prior[name])
            for name in universe}
