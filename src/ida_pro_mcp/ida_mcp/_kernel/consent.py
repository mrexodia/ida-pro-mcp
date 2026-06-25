"""Binary-patch consent gate (axis 7: never patch the analysed program unless
the user explicitly asks).

Rewriting the bytes of the program under analysis is fundamentally different
from annotating the IDB (renames, comments, types) — it is irreversible at the
source level and is never part of *understanding* a binary. So byte-writes are
fenced behind three independent layers:

1. SERVER GATE — patching is OFF by default. A human enables it out of band:
   set ``IDA_MCP_ALLOW_PATCH=1`` in the server's environment, or call
   :func:`set_patch_allowed`. The model driving the MCP client cannot flip
   this, so it faithfully models "the user explicitly authorized patching".
2. PER-CALL CONFIRM — even when the gate is open, byte-writers default to a
   dry-run *preview* and only write when the call passes ``confirm=True``. A
   patch therefore can never happen on reflex or from a single stray call.
3. REVERSIBILITY — every applied write first captures the original bytes (and
   IDA's native patched-byte store records them too), so the change can be
   reported back and reverted with :func:`revert_span`.

This gate is intentionally independent of the coarse ``--unsafe`` server flag
(which also turns on ordinary, reversible annotation tools): "unsafe is on"
must not silently mean "patching is invited".

The pure decision helpers (:func:`patching_allowed`, :func:`patch_decision`)
import no IDA modules and are unit-testable headlessly. The helpers that touch
the database import ``ida_bytes`` lazily.
"""

from __future__ import annotations

import contextlib
import os
from typing import Iterator, Optional

__all__ = [
    "set_patch_allowed",
    "patching_allowed",
    "patch_decision",
    "consent_hint",
    "withheld_hint",
    "span_status",
    "capture_original",
    "revert_span",
    "block_byte_writes",
    "PatchBlockedError",
    "PATCH_ENV_FLAG",
]


class PatchBlockedError(RuntimeError):
    """Raised when injected code attempts an image-byte write while patching is
    not explicitly allowed."""

PATCH_ENV_FLAG = "IDA_MCP_ALLOW_PATCH"
_TRUTHY = {"1", "true", "yes", "on"}

# Module-level override. None means "consult the environment variable".
_patch_allowed_override: Optional[bool] = None


def set_patch_allowed(allowed: Optional[bool]) -> None:
    """Set the server-level patch gate. ``None`` reverts to the env variable."""
    global _patch_allowed_override
    _patch_allowed_override = allowed


def patching_allowed() -> bool:
    """True when binary byte-writes are permitted by the server gate."""
    if _patch_allowed_override is not None:
        return _patch_allowed_override
    return os.environ.get(PATCH_ENV_FLAG, "").strip().lower() in _TRUTHY


def consent_hint() -> str:
    """Human/agent-facing explanation of why a write was withheld."""
    return (
        "Binary patching is disabled: the analysed program's bytes are never "
        "modified unless the user explicitly asks. To enable, the user sets "
        f"{PATCH_ENV_FLAG}=1 in the server environment (or calls "
        "set_patch_allowed(True)); then re-issue the write with confirm=true. "
        "The default dry_run=true preview reports what WOULD change without "
        "writing anything."
    )


def withheld_hint(reason: str) -> str:
    """Explain to the agent why a byte-write was previewed instead of applied.

    `reason` comes from :func:`patch_decision`. Shared by every byte-writer so the
    consent guidance reads identically across patch / put_int / patch_asm.
    """
    if reason == "server_gate_closed":
        return consent_hint()
    if reason == "dry_run":
        return (
            "Preview only (dry_run=true): nothing was written. Re-issue with "
            "dry_run=false and confirm=true to apply."
        )
    if reason == "confirm_required":
        return (
            "Preview only (confirm=false): nothing was written. Re-issue with "
            "confirm=true and dry_run=false to apply."
        )
    return ""


def patch_decision(confirm: bool, dry_run: bool) -> tuple[bool, str]:
    """Decide whether a byte-write may proceed.

    Returns ``(will_write, reason)``. ``will_write`` is True only when the
    server gate is open, ``dry_run`` is False, and ``confirm`` is True. The
    ``reason`` is one of ``server_gate_closed`` / ``dry_run`` /
    ``confirm_required`` / ``ok`` for inclusion in the tool response.
    """
    if not patching_allowed():
        return False, "server_gate_closed"
    if dry_run:
        return False, "dry_run"
    if not confirm:
        return False, "confirm_required"
    return True, "ok"


# ---------------------------------------------------------------------------
# Database-touching helpers (must run inside an @idasync context).
# ---------------------------------------------------------------------------


def span_status(ea: int, size: int) -> tuple[bool, Optional[int]]:
    """Return ``(all_mapped, first_unmapped_ea)`` for ``[ea, ea+size)``.

    Validates EVERY byte of the span, not just the start, so a write that would
    run off the end of a mapped region is rejected before any byte is touched.
    """
    import ida_bytes

    for offset in range(size):
        if not ida_bytes.is_mapped(ea + offset):
            return False, ea + offset
    return True, None


def capture_original(ea: int, size: int) -> Optional[str]:
    """Hex of the current bytes at ``[ea, ea+size)`` (read before a write), or None."""
    import ida_bytes

    data = ida_bytes.get_bytes(ea, size)
    return data.hex() if data else None


def revert_span(ea: int, size: int) -> int:
    """Revert IDA's patched bytes over ``[ea, ea+size)`` to their originals.

    Uses IDA's native patched-byte store (``revert_byte``), which restores the
    pre-patch value byte by byte. Returns the count of bytes actually reverted.
    """
    import ida_bytes

    reverted = 0
    for offset in range(size):
        if ida_bytes.revert_byte(ea + offset):
            reverted += 1
    return reverted


# The functions that write IMAGE bytes (the program under analysis). Restorative
# revert_byte is deliberately NOT listed — undoing a patch is always allowed.
_IMAGE_BYTE_WRITERS = {
    "ida_bytes": (
        "patch_bytes", "patch_byte", "patch_word", "patch_dword", "patch_qword",
        "put_byte", "put_word", "put_dword", "put_qword", "put_bytes",
    ),
    "idc": (
        "patch_byte", "patch_word", "patch_dword", "patch_qword", "patch_bytes",
    ),
}


@contextlib.contextmanager
def block_byte_writes() -> Iterator[None]:
    """Temporarily make IDA's image-byte-write functions raise PatchBlockedError.

    Used to fence injected Python (py_eval / py_exec_file) so a script cannot
    rewrite the analysed program's bytes unless patching was explicitly enabled.
    This swaps the attributes on the *actual* ``ida_bytes`` / ``idc`` module
    objects, so it holds even for a script that re-imports them, and restores the
    originals on exit. Restorative ``revert_byte`` is intentionally left working.
    """
    import importlib

    def _blocked(*_args, **_kwargs):
        raise PatchBlockedError(
            "Patching the analysed binary from an injected script is disabled. "
            "Re-run with allow_patch=true only if the user explicitly asked to "
            "patch the program's bytes (axis-7 never-patch-without-consent rule)."
        )

    saved: list[tuple[object, str, object]] = []
    try:
        for module_name, names in _IMAGE_BYTE_WRITERS.items():
            try:
                module = importlib.import_module(module_name)
            except Exception:
                continue
            for name in names:
                if hasattr(module, name):
                    saved.append((module, name, getattr(module, name)))
                    setattr(module, name, _blocked)
        yield
    finally:
        for module, name, original in saved:
            setattr(module, name, original)
