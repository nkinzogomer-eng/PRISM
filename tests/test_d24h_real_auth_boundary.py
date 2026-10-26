"""D2.4H real authorization verifier, including a negative mutation control."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.d24h_real_auth_boundary import verify_current_owner_boundary

ROUTE = """
@router.delete("/{id}")
def delete_item(session: SessionDep, current_user: CurrentUser, id: int) -> Message:
    item = session.get(Item, id)
    if not item:
        raise HTTPException(status_code=404, detail="not found")
    if not current_user.is_superuser and (item.owner_id != current_user.id):
        raise HTTPException(status_code=403, detail="not allowed")
    session.delete(item)
    session.commit()
    return Message(message="ok")
"""

DEPS = """
CurrentUser = Annotated[User, Depends(get_current_user)]
def get_current_user(token):
    payload = jwt.decode(token, secret)
    if not payload:
        raise HTTPException(status_code=403, detail="bad")
    return user
"""


class SourceAuthorizationProof(unittest.TestCase):
    def run_sources(self, route=ROUTE, deps=DEPS):
        with TemporaryDirectory() as d:
            p=Path(d)/"route.py"
            q=Path(d)/"deps.py"
            p.write_text(route)
            q.write_text(deps)
            return verify_current_owner_boundary(p,q)

    def test_reproduces_isolated_owner_boundary_without_external_db(self):
        r=self.run_sources()
        self.assertEqual(r["status"],"LOCAL_AUTH_BOUNDARY_OBSERVED")
        self.assertTrue(all(r["independent_runtime_checks"].values()))
        self.assertEqual(r["observations"]["nonowner"]["db_effects"],["read"])
        self.assertEqual(r["observations"]["owner"]["db_effects"],
                         ["read","delete","commit"])
        self.assertFalse(r["auth_resolver_actually_executed"])
        self.assertFalse(r["new_unpublished_vulnerability_confirmed"])

    def test_nonowner_side_effect_before_auth_is_detected_by_oracle(self):
        bad=ROUTE.replace(
            "    if not current_user.is_superuser and",
            "    session.delete(item)\n    if not current_user.is_superuser and",
        )
        r=self.run_sources(route=bad)
        self.assertEqual(r["status"],"LOCAL_AUTH_PROPERTY_VIOLATION_OBSERVED")
        self.assertFalse(r["independent_runtime_checks"]["nonowner_denied_403_without_write"])

    def test_dependency_not_resolvable_does_not_mean_safe(self):
        with self.assertRaisesRegex(ValueError,"dependency resolution UNKNOWN"):
            self.run_sources(deps=DEPS.replace(
                "Depends(get_current_user)","Depends(unresolved_identity)"))

    def test_unrecognized_route_refuses_guess(self):
        with self.assertRaisesRegex(ValueError,"unsupported or ambiguous"):
            self.run_sources(route="def add_item(x):return x")


if __name__=="__main__":
    unittest.main()
