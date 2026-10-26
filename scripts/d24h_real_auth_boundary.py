"""D2.4H: independently execute a *current real* FastAPI route's auth boundary.

Unmodified third-party AST body, fake in-memory DB, no server, real DB,
network access, user information, authentication token or side effects.

The hypothesized owner/caller relationship is discovered from local route
shape and its imported annotation's provenance in a second source module.
This checks a narrow *route-level* property only; it does NOT attest that the
real framework injected a correctly authenticated caller or that the entire
application has no authorization bypass.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
from time import perf_counter
from types import SimpleNamespace


class LocalHTTPException(Exception):
    def __init__(self, *, status_code: int, detail: str = ""):
        super().__init__(detail)
        self.status_code=status_code


def _actual_delete_route(source: str) -> ast.FunctionDef:
    tree=ast.parse(source)
    found=[]
    for node in tree.body:
        if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            continue
        decorators=[ast.unparse(d) for d in node.decorator_list]
        if not any(".delete(" in d for d in decorators):
            continue
        operations=[ast.unparse(n.func) for n in ast.walk(node)
                    if isinstance(n,ast.Call)]
        if ("session.delete" in operations and
            "session.commit" in operations and
            "current_user" in ast.unparse(node)):
            found.append(node)
    if len(found)!=1 or not isinstance(found[0],ast.FunctionDef):
        raise ValueError("unsupported or ambiguous local resource-delete route")
    return found[0]


def _provenance(deps_source: str, route: ast.FunctionDef) -> dict:
    tree=ast.parse(deps_source)
    exported_annotations={}
    for node in tree.body:
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name):
                    exported_annotations[target.id]=ast.unparse(node.value)
    route_annotations={x.arg:ast.unparse(x.annotation)
                       for x in [*route.args.args,*route.args.kwonlyargs]
                       if x.annotation is not None}
    alias=route_annotations.get("current_user")
    if not alias:
        raise ValueError("auth dependency type not visible in route signature")
    declaration=exported_annotations.get(alias)
    if not declaration or "Depends(get_current_user)" not in declaration:
        raise ValueError("auth dependency resolution UNKNOWN / missing")
    resolver=[n for n in tree.body
              if isinstance(n,ast.FunctionDef) and n.name=="get_current_user"]
    if len(resolver)!=1:
        raise ValueError("auth resolver definition absent or ambiguous")
    symbols=ast.unparse(resolver[0])
    if "jwt.decode" not in symbols or "HTTPException" not in symbols:
        raise ValueError("incomplete authentication resolver semantics")
    # This is an observed SOURCE LINK, not a runtime security guarantee.
    return {"alias":alias,"route_parameter":"current_user",
            "dependency":"Depends(get_current_user)",
            "jwt_decode_present":True,"may_be_overridden_or_configured":True,
            "verification_state":"STATIC_PROVENANCE_UNVERIFIED"}


def _compile_original_route(route: ast.FunctionDef):
    original=ast.fix_missing_locations(ast.Module(body=[
        ast.ImportFrom(module="__future__",
                       names=[ast.alias(name="annotations")],level=0),
        ast.FunctionDef(name=route.name,args=route.args,body=route.body,
                        decorator_list=[],returns=route.returns,
                        type_comment=route.type_comment,
                        type_params=getattr(route,"type_params",[]))
    ],type_ignores=[]))
    scope={"Item":object(),
           "HTTPException":LocalHTTPException,
           "Message":lambda **fields:SimpleNamespace(**fields)}
    exec(compile(original,"<pinned-original-route-ast>","exec"),scope)
    return scope[route.name]


class FakeSession:
    def __init__(self,record):
        self.record=record
        self.events=[]
    def get(self,model,key):
        self.events.append("read")
        return self.record
    def delete(self,record):
        self.events.append("delete")
    def commit(self):
        self.events.append("commit")


def verify_current_owner_boundary(route_path: Path,
                                  deps_path: Path,
                                  *, out: Path | None = None) -> dict:
    start=perf_counter()
    raw=route_path.read_bytes()
    depraw=deps_path.read_bytes()
    route=_actual_delete_route(raw.decode())
    dependency=_provenance(depraw.decode(),route)
    source=ast.unparse(route)
    if not all(k in source for k in ("owner_id","current_user.is_superuser","HTTPException")):
        raise ValueError("owner-vs-superuser security property is not derived from this source")
    run=_compile_original_route(route)
    def attempt(user_id:int, owner_id:int, *,
                is_superuser:bool=False, exists:bool=True):
        record=SimpleNamespace(owner_id=owner_id) if exists else None
        db=FakeSession(record)
        caller=SimpleNamespace(id=user_id,is_superuser=is_superuser)
        try:
            result=run(db,caller,"dummy-object-id")
            outcome="SUCCESS"
            status_code=None
            _=result
        except LocalHTTPException as e:
            outcome="REJECTED"
            status_code=e.status_code
        return {"caller_id":user_id,"owner_id":owner_id,
                "admin":is_superuser,"object_exists":exists,
                "outcome":outcome,"http_status":status_code,
                "db_effects":db.events}
    samples={
        "nonowner":attempt(100,200),
        "owner":attempt(200,200),
        "admin":attempt(100,200,is_superuser=True),
        "missing":attempt(100,200,exists=False),
    }
    outsider=samples["nonowner"]
    owner=samples["owner"]
    admin=samples["admin"]
    missing=samples["missing"]
    checks={
        "nonowner_denied_403_without_write": outsider["outcome"]=="REJECTED" and
            outsider["http_status"]==403 and outsider["db_effects"]==["read"],
        "owner_allowed_one_delete_commit":owner["outcome"]=="SUCCESS" and
            owner["db_effects"]==["read","delete","commit"],
        "administrator_allowed_one_delete_commit":admin["outcome"]=="SUCCESS" and
            admin["db_effects"]==["read","delete","commit"],
        "nonexistent_object_denied_404_without_write":missing["outcome"]=="REJECTED" and
            missing["http_status"]==404 and missing["db_effects"]==["read"],
    }
    if sha256(route_path.read_bytes()).digest()!=sha256(raw).digest():
        raise RuntimeError("third-party route source modified")
    if sha256(deps_path.read_bytes()).digest()!=sha256(depraw).digest():
        raise RuntimeError("third-party dependency source modified")
    result={
        "schema":"scm.prism.d24h.real-auth-invariant.v1",
        "status":"LOCAL_AUTH_BOUNDARY_OBSERVED" if all(checks.values())
                 else "LOCAL_AUTH_PROPERTY_VIOLATION_OBSERVED",
        "target":"real_third_party_source_ast",
        "sha256":{"route":sha256(raw).hexdigest(),
                  "dependencies":sha256(depraw).hexdigest()},
        "route_name":route.name,"source_line":route.lineno,
        "hypothesis":"Nonowners must not delete objects they do not own",
        "auth_dependency_provenance":dependency,
        "independent_runtime_checks":checks,
        "observations":samples,
        "bound_to_actual_http_framework":False,
        "auth_resolver_actually_executed":False,
        "external_db_modified":False,
        "new_unpublished_vulnerability_confirmed":False,
        "absence_of_all_auth_vulnerabilities_proved":False,
        "duration_seconds":perf_counter()-start,
    }
    if out is not None:
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print("D24H_REAL_AUTHORIZATION",json.dumps({
        "status":result["status"],"checks":checks,
        "dependency":dependency["dependency"],
        "new_bugs":0,
    },sort_keys=True))
    return result


if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--route",type=Path,required=True)
    p.add_argument("--deps",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    verify_current_owner_boundary(a.route,a.deps,out=a.out)
