# ---------------------------------------------------------------------------
# PRISM Cyber Range — transaction authorisation policy (real OPA/Rego)
#
# This is the "authorisation de transaction" step of the reference chain. It is
# deliberately written the way an exchange writes these controls: layered
# limits, destination allowlists, quorum for large transfers, velocity caps and
# an emergency revocation list.
#
# Everything here is *enforced by the same engine class used in production*
# (OPA). The policy is not a mock: if it says allow, the signer proceeds.
#
# Findings the lab expects to make possible:
#   * policy/implementation drift (service checks a different decision path)
#   * missing checks on a rarely used asset/route
#   * velocity limit evaluated per-approver instead of per-account
#   * revocation list consulted at submit time but not at sign time
# ---------------------------------------------------------------------------
package prism.tx

import future.keywords.in
import future.keywords.every

default allow := false

# --- inputs ----------------------------------------------------------------
# input.request = {
#   "account_id": "...", "asset": "ETH", "amount": "12.5",
#   "destination": "0x..", "chain_id": 31337,
#   "approvals": [{"actor":"alice","role":"treasury"}, ...],
#   "session": {"actor":"ops1","mfa":"webauthn","age_s":42},
#   "signer": {"key_id":"...", "hsm_token":"prism-signer"},
#   "time_utc": "2026-10-29T20:24:23Z"
# }
# data.limits, data.destinations, data.revoked_keys, data.velocity are loaded
# from JSON in range/config/opa/data/.

# --- hard stops ------------------------------------------------------------
deny_reason["signer key is revoked"] {
	some key in data.revoked_keys
	key == input.request.signer.key_id
}

deny_reason["destination not allowlisted for asset"] {
	not input.request.destination in data.destinations[input.request.asset]
}

deny_reason["session older than step-up window"] {
	input.request.session.age_s > data.limits.max_session_age_s
}

deny_reason["session lacks MFA"] {
	input.request.session.mfa == "none"
}

deny_reason["amount above absolute ceiling"] {
	to_number(input.request.amount) > data.limits.absolute_ceiling[input.request.asset]
}

# Velocity: sum of this account's outflow in the last hour, including this one.
deny_reason["hourly velocity cap exceeded"] {
	window := [tx | some tx in data.velocity.recent[input.request.account_id]]
	sum_window := sum([to_number(tx.amount) | some tx in window])
	sum_window + to_number(input.request.amount) >
		data.limits.hourly_cap[input.request.asset]
}

# A demo-mode quorum: >=2 distinct approvers for anything above the threshold.
deny_reason["quorum not met for large transfer"] {
	to_number(input.request.amount) > data.limits.quorum_threshold[input.request.asset]
	distinct := {a.actor | some a in input.request.approvals}
	count(distinct) < 2
}

deny_reason["approver is the requester"] {
	some a in input.request.approvals
	a.actor == input.request.session.actor
}

# --- decision --------------------------------------------------------------
allow {
	count(deny_reason) == 0
}

reasons := [r | some r in deny_reason]

# Structured audit record: the Blue Team depends on this being emitted even on
# denial, because a denied transaction is often the first signal.
decision := {
	"allow": allow,
	"reasons": reasons,
	"account_id": input.request.account_id,
	"asset": input.request.asset,
	"amount": input.request.amount,
	"destination": input.request.destination,
	"actor": input.request.session.actor,
	"time_utc": input.request.time_utc,
}
