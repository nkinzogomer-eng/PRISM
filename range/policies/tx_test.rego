# Policy tests. Run on a host with OPA:
#   opa test range/policies -v
# The lab treats a failing policy test as a broken guardrail, so these are part
# of the acceptance criteria for scenario S2/S4, not decoration.
package prism.tx_test

import future.keywords.in

good_request := {
	"account_id": "acct-hot-1",
	"asset": "ETH",
	"amount": "2.5",
	"destination": "0x00000000000000000000000000000000000000aa",
	"chain_id": 31337,
	"approvals": [],
	"session": {"actor": "ops1", "mfa": "webauthn", "age_s": 30},
	"signer": {"key_id": "k-signer-1", "hsm_token": "prism-signer"},
	"time_utc": "2026-10-29T20:24:23Z",
}

limits := {
	"max_session_age_s": 300,
	"absolute_ceiling": {"ETH": 1000, "USDT": 1000000},
	"quorum_threshold": {"ETH": 100, "USDT": 250000},
	"hourly_cap": {"ETH": 200, "USDT": 500000},
}

destinations := {"ETH": ["0x00000000000000000000000000000000000000aa"], "USDT": []}

test_small_transfer_allowed {
	result := prism.tx.allow with input as {"request": good_request} with data.limits as limits
		with data.destinations as destinations with data.revoked_keys as []
		with data.velocity as {"recent": {"acct-hot-1": []}}
	result == true
}

test_unknown_destination_denied {
	bad := object.union(good_request, {"destination": "0x00000000000000000000000000000000000000bb"})
	result := prism.tx.deny_reason with input as {"request": bad} with data.limits as limits
		with data.destinations as destinations with data.revoked_keys as []
		with data.velocity as {"recent": {"acct-hot-1": []}}
	"destination not allowlisted for asset" in result
}

test_revoked_key_denied {
	revoked := ["k-signer-1"]
	result := prism.tx.deny_reason with input as {"request": good_request} with data.limits as limits
		with data.destinations as destinations with data.revoked_keys as revoked
		with data.velocity as {"recent": {"acct-hot-1": []}}
	"signer key is revoked" in result
}

test_velocity_cap_denied {
	velocity := {"recent": {"acct-hot-1": [{"amount": "199"}, {"amount": "1"}]}}
	result := prism.tx.deny_reason with input as {"request": good_request} with data.limits as limits
		with data.destinations as destinations with data.revoked_keys as []
		with data.velocity as velocity
	"hourly velocity cap exceeded" in result
}

test_large_transfer_needs_quorum {
	large := object.union(good_request, {"amount": "150"})
	result := prism.tx.deny_reason with input as {"request": large} with data.limits as limits
		with data.destinations as destinations with data.revoked_keys as []
		with data.velocity as {"recent": {"acct-hot-1": []}}
	"quorum not met for large transfer" in result
}

test_self_approval_rejected {
	large := object.union(good_request, {
		"amount": "150",
		"approvals": [{"actor": "ops1", "role": "treasury"}],
	})
	result := prism.tx.deny_reason with input as {"request": large} with data.limits as limits
		with data.destinations as destinations with data.revoked_keys as []
		with data.velocity as {"recent": {"acct-hot-1": []}}
	"approver is the requester" in result
}
