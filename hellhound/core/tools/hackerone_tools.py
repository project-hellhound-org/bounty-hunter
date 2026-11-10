"""
hellhound/core/tools/hackerone_tools.py - HackerOne Hacktivity / program-intel.

Split slice 4 from agent.py. Three thin tools (search disclosed reports, fetch a
program's policy/scopes, fetch its stats) over hellhound.mcp.hackerone_mcp -
which is imported LAZILY inside each tool, so there's no import coupling - plus
their shared error humanizer. No agent.py internals. agent.py re-imports all four
names so TOOL_REGISTRY wiring is unchanged.
"""
from typing import Any, Dict

from hellhound.core.tasks import Target


def _humanize_hackerone_error(action: str, program: str, e: Exception) -> Dict[str, Any]:
    """
    Turns a HackerOneAPIError (or any other exception from the hackerone_mcp
    calls) into the same status+note, self-talk voice used elsewhere for
    "this went wrong in a way you should understand and not just retry
    blindly" tool results (see jwt_forge's not_a_jwt case, set_target's
    validation errors) — instead of dumping the raw GraphQL error structure
    or a generic Python exception string straight to the researcher.
    """
    msg = str(e)
    low = msg.lower()
    if "does not exist" in low or "not found" in low:
        return {
            "status": "program_not_found",
            "note": f"Nah bro, HackerOne doesn't have a program under the handle '{program}' — {action} needs the exact URL slug from the program's HackerOne page (hackerone.com/<handle>), not the display name. Double-check the handle there and retry; if it's genuinely not on HackerOne, it may be listed on Bugcrowd/Intigriti/another platform instead.",
        }
    if "timeout" in low or "timed out" in low:
        return {
            "status": "timeout",
            "note": f"Nah bro, the {action} call to HackerOne timed out — their API was slow or unreachable just now, not a problem with the program handle. Worth one retry; if it keeps timing out, move on and come back to it later.",
        }
    return {
        "status": "api_error",
        "note": f"Nah bro, the {action} call to HackerOne's API came back with an error, not real data: {msg}. Don't treat this as 'program has no policy/stats' — it's an API-level failure, so don't record anything based on it.",
    }


def _execute_hackerone_search(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Search HackerOne Hacktivity for disclosed vulnerability reports."""
    keyword = args.get("keyword", "")
    program = args.get("program", "")
    limit = args.get("limit", 10)
    
    try:
        from hellhound.mcp.hackerone_mcp.server import search_disclosed_reports
        results = search_disclosed_reports(keyword=keyword, program=program, limit=limit)
        return {"status": "success", "results": results, "count": len(results)}
    except Exception as e:
        return _humanize_hackerone_error("hackerone_search", program, e)


def _execute_hackerone_policy(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Get the public policy and scopes for a HackerOne program."""
    program = args.get("program", "") or target.name.split(".")[0]
    
    try:
        from hellhound.mcp.hackerone_mcp.server import get_program_policy
        result = get_program_policy(program)
        if "error" in result:
            return {
                "status": "program_not_found",
                "note": f"Nah bro, HackerOne doesn't have a program under the handle '{program}' — hackerone_policy needs the exact URL slug from the program's HackerOne page (hackerone.com/<handle>), not the display name. Double-check the handle there and retry.",
            }
        return {"status": "success", "policy": result}
    except Exception as e:
        return _humanize_hackerone_error("hackerone_policy", program, e)


def _execute_hackerone_stats(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """Get public statistics (bounties, response times, resolved reports) for a HackerOne program."""
    program = args.get("program", "") or target.name.split(".")[0]
    
    try:
        from hellhound.mcp.hackerone_mcp.server import get_program_stats
        result = get_program_stats(program)
        if "error" in result:
            return {
                "status": "program_not_found",
                "note": f"Nah bro, HackerOne doesn't have a program under the handle '{program}' — hackerone_stats needs the exact URL slug from the program's HackerOne page (hackerone.com/<handle>), not the display name. Double-check the handle there and retry.",
            }
        return {"status": "success", "stats": result}
    except Exception as e:
        return _humanize_hackerone_error("hackerone_stats", program, e)
