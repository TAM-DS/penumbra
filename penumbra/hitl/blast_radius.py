"""Layer 5: the counterfactual simulator.

Before anyone clicks Approve, they should see what will break. The
simulator predicts the blast radius of a containment action from the
dependency map (service accounts → pipelines, users → on-call duties) and
the observed telemetry (which pipelines actually authenticate with which
key), and it suggests a narrower alternative when one exists.
"""

from __future__ import annotations

from typing import Any

from ..telemetry import world


def _pipelines_using_key(ctx, key: str) -> list[str]:
    return sorted({e.attrs["pipeline"] for e in ctx.events
                   if e.attrs.get("access_key") == key and e.attrs.get("pipeline")})


def simulate(ctx, tool: str, target: str) -> dict[str, Any]:
    out: dict[str, Any] = {"tool": tool, "target": target, "pipelines_halted": [],
                           "users_affected": [], "reversible": True, "alternatives": [],
                           "notes": []}
    if tool == "revoke_access_key":
        used_by = _pipelines_using_key(ctx, target)
        out["pipelines_halted"] = used_by
        owner = next((sa for sa in world.SERVICE_ACCOUNTS
                      if any(e.attrs.get("access_key") == target and e.actor == sa
                             for e in ctx.events)), None)
        if owner:
            all_p = world.SERVICE_ACCOUNTS[owner]["pipelines"]
            out["alternatives"].append(
                f"Disabling all of {owner} would halt {len(all_p)} CI/CD pipelines "
                f"({', '.join(all_p)}). Revoking only this key halts "
                f"{len(used_by) or 'none'}: the pipelines authenticate with a different key.")
        out["summary"] = (f"Revoking {target} halts {len(used_by)} pipelines"
                          + (f": {', '.join(used_by)}" if used_by else "") + ". Reversible.")
    elif tool == "suspend_user":
        dep = world.USER_DEPENDENCIES.get(target, {})
        out["users_affected"] = [target]
        out["notes"] = [f"owns {dep.get('repos_owned', 0)} repos",
                        f"on-call: {', '.join(dep.get('oncall_rotations', [])) or 'none'}",
                        f"scheduled jobs: {', '.join(dep.get('scheduled_jobs', [])) or 'none'}"]
        emp = world.EMPLOYEES.get(target)
        out["protected_principal"] = bool(emp and emp.protected)
        out["summary"] = (f"Suspending {target} removes access to {dep.get('repos_owned', 0)} repos, "
                          f"leaves {len(dep.get('oncall_rotations', []))} on-call rotation uncovered "
                          f"and pauses {len(dep.get('scheduled_jobs', []))} scheduled job. "
                          "HR and Legal should be notified before execution.")
        out["alternatives"].append("Force MFA re-auth + revoke sessions keeps the account "
                                   "available for interview while cutting live access.")
    elif tool == "force_mfa_reauth":
        out["users_affected"] = [target]
        out["summary"] = f"{target} is signed out of all sessions and must re-enroll MFA (~5 min)."
    elif tool == "block_domain":
        legit = [e for e in ctx.events if e.ts < ctx.window_start and target in (e.actor or "")]
        out["summary"] = (f"Blocking {target}: {len(legit)} legitimate messages from this domain "
                          "in the baseline window. No business impact expected.")
    elif tool == "remove_bucket_policy":
        out["summary"] = (f"Removes cross-account grant on {target}. Internal readers unaffected; "
                          "external account loses access immediately.")
    elif tool == "deploy_canary":
        out["summary"] = ("No production impact. Decoy is inert unless an adversary reads and "
                          "uses it, which fires an attribution beacon.")
        out["notes"].append("Decoy naming mirrors the staged files so it's indistinguishable "
                            "from the real data to the adversary.")
    elif tool == "isolate_endpoint":
        out["summary"] = f"{target} loses all network access except the EDR channel."
    else:
        out["summary"] = "No model for this action. Treat the blast radius as unknown."
        out["reversible"] = False
    return out
