"""Persistent analysis notebook stored in IDA netnodes.

Data survives across MCP sessions and is saved with the IDB file.
"""

import json
import logging

from typing import Annotated

import ida_funcs
import ida_netnode
import idautils

from .rpc import tool, unsafe
from .sync import idasync, IDAError
from .utils import parse_address, normalize_list_input

# Netnode name — the "$ " prefix is the IDA convention for plugin data.
_NOTEBOOK_NODE = "$ ida_mcp.notebook"
_BACKUP_NODE = "$ ida_mcp.notebook.backup"

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Storage backend
# ---------------------------------------------------------------------------

def _default_notebook() -> dict:
    return {
        "modules": {},
        "hypotheses": [],
        "annotations": {},
        "progress": {
            "functions_analyzed": 0,
            "functions_total": 0,
            "functions_named": 0,
        },
    }


def _backup_corrupt_blob(raw: bytes) -> None:
    """Save corrupt notebook blob to a separate netnode for recovery."""
    try:
        node = ida_netnode.netnode(_BACKUP_NODE, 0, True)
        node.setblob(raw, 0, "N")
        logger.warning("Corrupt notebook blob backed up to '%s'", _BACKUP_NODE)
    except Exception:
        logger.error("Failed to back up corrupt notebook blob", exc_info=True)


def _has_corrupt_backup() -> bool:
    """Return True if a corrupt-blob backup exists."""
    node = ida_netnode.netnode(_BACKUP_NODE, 0, False)
    if node == ida_netnode.BADNODE:
        return False
    return node.getblob(0, "N") is not None


# Expected types for each top-level notebook key.
_NOTEBOOK_SCHEMA: dict[str, type] = {
    "modules": dict,
    "hypotheses": list,
    "annotations": dict,
    "progress": dict,
}


def _validate_notebook(data: dict) -> dict:
    """Ensure each top-level key has the correct type.

    Keys with wrong types are replaced with their defaults.
    Missing keys are back-filled via setdefault."""
    defaults = _default_notebook()
    for key, val in defaults.items():
        data.setdefault(key, val)
    for key, expected_type in _NOTEBOOK_SCHEMA.items():
        if not isinstance(data.get(key), expected_type):
            logger.warning(
                "Notebook key '%s' has wrong type %s, expected %s; resetting to default",
                key, type(data.get(key)).__name__, expected_type.__name__,
            )
            data[key] = defaults[key]
    return data


def _load_notebook() -> dict:
    node = ida_netnode.netnode(_NOTEBOOK_NODE, 0, True)
    blob = node.getblob(0, "N")
    if blob is None:
        return _default_notebook()

    raw = bytes(blob)
    try:
        data = json.loads(raw)
    except Exception:
        logger.warning("Notebook blob is not valid JSON; backing up and resetting")
        _backup_corrupt_blob(raw)
        return _default_notebook()

    if not isinstance(data, dict):
        logger.warning(
            "Notebook blob decoded to %s instead of dict; backing up and resetting",
            type(data).__name__,
        )
        _backup_corrupt_blob(raw)
        return _default_notebook()

    return _validate_notebook(data)


def _save_notebook(data: dict):
    node = ida_netnode.netnode(_NOTEBOOK_NODE, 0, True)
    node.setblob(json.dumps(data).encode("utf-8"), 0, "N")


def _compute_progress() -> dict:
    """Live progress stats from the IDB (not cached)."""
    total = 0
    named = 0
    commented = 0
    for ea in idautils.Functions():
        total += 1
        fn = ida_funcs.get_func(ea)
        if fn is None:
            continue
        name = ida_funcs.get_func_name(ea)
        if name and not name.startswith("sub_"):
            named += 1
        cmt = ida_funcs.get_func_cmt(fn, False) or ida_funcs.get_func_cmt(fn, True)
        if cmt:
            commented += 1
    return {
        "functions_total": total,
        "functions_named": named,
        "functions_commented": commented,
        "functions_analyzed": named,  # named ≈ analyzed for progress tracking
    }


# ---------------------------------------------------------------------------
# Tool 1: notebook_status
# ---------------------------------------------------------------------------

@tool
@idasync
def notebook_status() -> dict:
    """Return the full analysis notebook plus live progress statistics.

    The notebook persists across MCP sessions (stored in the IDB).
    Progress stats are recomputed each call from the current IDB state."""
    nb = _load_notebook()
    nb["progress"] = _compute_progress()
    nb["corrupt_backup"] = _has_corrupt_backup()
    return nb


# ---------------------------------------------------------------------------
# Tool 2: notebook_add_module
# ---------------------------------------------------------------------------

@tool
@idasync
def notebook_add_module(
    name: Annotated[str, "Module name (e.g. 'crypto', 'network')"],
    functions: Annotated[list[str], "Function addresses belonging to this module"],
    confidence: Annotated[float, "Confidence 0.0-1.0"] = 1.0,
    evidence: Annotated[str, "Evidence for classification"] = "",
) -> dict:
    """Register a discovered module/component in the analysis notebook.

    Groups related functions under a logical module name with
    confidence scoring and supporting evidence."""
    nb = _load_notebook()
    addrs = [hex(parse_address(a)) for a in normalize_list_input(functions)]
    entry = {
        "functions": addrs,
        "confidence": max(0.0, min(1.0, confidence)),
        "evidence": evidence,
    }
    nb["modules"][name] = entry
    _save_notebook(nb)
    return {"module": name, **entry}


# ---------------------------------------------------------------------------
# Tool 3: notebook_add_hypothesis
# ---------------------------------------------------------------------------

@tool
@idasync
def notebook_add_hypothesis(
    claim: Annotated[str, "What is being claimed"],
    addr: Annotated[str, "Related address"] = "",
    evidence: Annotated[str, "Supporting evidence"] = "",
    status: Annotated[str, "'proposed', 'testing', 'verified', 'rejected'"] = "proposed",
) -> dict:
    """Record an analysis hypothesis in the notebook.

    Hypotheses track claims about the binary under analysis,
    with status progression from proposed → testing → verified/rejected."""
    _VALID_STATUSES = {"proposed", "testing", "verified", "rejected"}
    if status not in _VALID_STATUSES:
        raise IDAError(f"Invalid status '{status}', must be one of {sorted(_VALID_STATUSES)}")

    nb = _load_notebook()
    # Auto-increment ID based on existing max.
    existing_ids = [h["id"] for h in nb["hypotheses"] if "id" in h]
    next_id = (max(existing_ids) + 1) if existing_ids else 1

    resolved_addr = ""
    if addr:
        resolved_addr = hex(parse_address(addr))

    entry = {
        "id": next_id,
        "claim": claim,
        "status": status,
        "evidence": evidence,
        "addr": resolved_addr,
    }
    nb["hypotheses"].append(entry)
    _save_notebook(nb)
    return entry


# ---------------------------------------------------------------------------
# Tool 4: notebook_update_hypothesis
# ---------------------------------------------------------------------------

@tool
@idasync
def notebook_update_hypothesis(
    hypothesis_id: Annotated[int, "Hypothesis ID"],
    status: Annotated[str, "New status"] = "",
    evidence: Annotated[str, "Additional evidence"] = "",
) -> dict:
    """Update an existing hypothesis's status or evidence.

    Use to advance a hypothesis through proposed → testing → verified/rejected,
    or to append new supporting evidence."""
    _VALID_STATUSES = {"proposed", "testing", "verified", "rejected"}

    nb = _load_notebook()
    for h in nb["hypotheses"]:
        if h.get("id") == hypothesis_id:
            if status:
                if status not in _VALID_STATUSES:
                    raise IDAError(
                        f"Invalid status '{status}', must be one of {sorted(_VALID_STATUSES)}"
                    )
                h["status"] = status
            if evidence:
                # Append to existing evidence, separated by newline.
                prev = h.get("evidence", "")
                h["evidence"] = f"{prev}\n{evidence}".strip()
            _save_notebook(nb)
            return h
    return {"error": f"Hypothesis with id {hypothesis_id} not found"}


# ---------------------------------------------------------------------------
# Tool 5: notebook_annotate
# ---------------------------------------------------------------------------

@tool
@idasync
def notebook_annotate(
    addr: Annotated[str, "Address to annotate"],
    purpose: Annotated[str, "Identified purpose"] = "",
    notes: Annotated[str, "Additional notes"] = "",
) -> dict:
    """Add persistent notes about an address in the analysis notebook.

    Annotations survive across sessions and are saved with the IDB.
    Use to record identified purposes, observations, or context for addresses."""
    ea = parse_address(addr)
    key = hex(ea)

    nb = _load_notebook()
    existing = nb["annotations"].get(key, {})
    if purpose:
        existing["purpose"] = purpose
    if notes:
        existing["notes"] = notes
    nb["annotations"][key] = existing
    _save_notebook(nb)
    return {"addr": key, **existing}


# ---------------------------------------------------------------------------
# Tool 6: notebook_get_context
# ---------------------------------------------------------------------------

@tool
@idasync
def notebook_get_context(
    scope_addrs: Annotated[list[str] | str, "Addresses in current scope"],
) -> dict:
    """Get a compressed briefing for a set of addresses.

    Returns only notebook entries (modules, hypotheses, annotations)
    relevant to the given scope addresses. Useful for resuming analysis
    or understanding what is already known about a region."""
    nb = _load_notebook()
    addrs = normalize_list_input(scope_addrs)
    scope = {hex(parse_address(a)) for a in addrs}

    # Modules whose function lists overlap with scope.
    relevant_modules = {}
    for mod_name, mod in nb.get("modules", {}).items():
        overlap = [f for f in mod.get("functions", []) if f in scope]
        if overlap:
            relevant_modules[mod_name] = mod

    # Hypotheses tied to addresses in scope.
    relevant_hypotheses = [
        h for h in nb.get("hypotheses", [])
        if h.get("addr") in scope
    ]

    # Annotations for addresses in scope.
    relevant_annotations = {
        a: nb["annotations"][a]
        for a in scope
        if a in nb.get("annotations", {})
    }

    return {
        "modules": relevant_modules,
        "hypotheses": relevant_hypotheses,
        "annotations": relevant_annotations,
    }


# ---------------------------------------------------------------------------
# Tool 7: notebook_clear
# ---------------------------------------------------------------------------

@tool
@idasync
@unsafe
def notebook_clear() -> dict:
    """Reset the analysis notebook to its default empty state.

    WARNING: This permanently deletes all modules, hypotheses, and
    annotations stored in the notebook. The data cannot be recovered
    unless the IDB was saved beforehand."""
    nb = _default_notebook()
    _save_notebook(nb)
    return {"status": "cleared"}
