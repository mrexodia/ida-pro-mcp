from typing import Annotated, NotRequired, TypedDict

import ida_bytes
import ida_dirtree
import ida_frame
import ida_funcs
import ida_hexrays
import ida_name
import ida_typeinf
import ida_ua
import idaapi
import idautils
import idc

from .api_core import invalidate_strings_cache
from .compat import tinfo_get_udm
from .consent import (
    capture_original,
    patch_decision,
    patching_allowed,
    span_status,
    withheld_hint,
)
from .rpc import tool, safety, title
from .sync import idasync, IDAError
from .utils import (
    parse_address,
    decompile_checked,
    refresh_decompiler_ctext,
    hexrays_local_var_exists,
    CommentOp,
    CommentAppendOp,
    AsmPatchOp,
    FunctionRename,
    GlobalRename,
    LocalRename,
    StackRename,
    RenameBatch,
    DefineOp,
    UndefineOp,
)

MAX_BOOKMARK_SLOTS = 1024
BOOKMARK_PREFIX = "idaMCP: "


class CommentResult(TypedDict):
    addr: str
    error: NotRequired[str]


class AppendCommentResult(TypedDict):
    addr: str
    scope: NotRequired[str]
    appended: NotRequired[bool]
    skipped: NotRequired[bool]
    error: NotRequired[str]


class PatchAsmResult(TypedDict, total=False):
    addr: str | None
    size: int
    original: str  # hex of the bytes currently at addr (pre-write)
    new: str  # hex of the assembled bytes that were / would be written
    applied: bool  # whether THIS item was actually written
    tail_orphan_bytes: int  # stale bytes left when the patch is shorter than the original
    error: str


class PatchAsmResponse(TypedDict, total=False):
    applied: bool  # whether ANY byte was actually written this call
    dry_run: bool
    allowed: bool  # server-level patch gate state
    reason: str  # ok | dry_run | confirm_required | server_gate_closed
    consent: str  # guidance shown when the write was withheld
    results: list[PatchAsmResult]


class RenameItemResult(TypedDict, total=False):
    addr: str
    func_addr: str
    old: str
    new: str | None
    name: str
    dir: str
    dir_error: str
    dry_run: bool
    error: str


class RenameSummaryResult(TypedDict, total=False):
    total: int
    ok: int
    failed: int
    stopped: bool
    dry_run: bool
    allow_overwrite: bool
    stop_on_error: bool
    stopped_at: str


class RenameResult(TypedDict, total=False):
    func: list[RenameItemResult]
    data: list[RenameItemResult]
    global_alias: list[RenameItemResult]
    local: list[RenameItemResult]
    stack: list[RenameItemResult]
    summary: RenameSummaryResult


class DefineResult(TypedDict, total=False):
    addr: str
    ea: str
    start: str
    end: str
    size: int
    length: int
    error: str


class BookmarkResult(TypedDict, total=False):
    addr: str
    ea: str
    slot: int | None
    title: str
    prefix: str
    ok: bool
    error: str


# ============================================================================
# Modification Operations
# ============================================================================


@safety("WRITE")
@title("Add Or Replace Bookmark")
@tool
@idasync
def add_bookmark(
    addr: Annotated[str, "Address (hex/decimal/symbol) to attach the bookmark to"],
    name: Annotated[str, "Bookmark label text placed after the prefix"],
    prefix: Annotated[
        str,
        "Optional title prefix. Defaults to 'idaMCP: '; pass '' for no prefix.",
    ] = BOOKMARK_PREFIX,
) -> BookmarkResult:
    """WHAT: Add or replace an IDA navigation bookmark (Ctrl-1 marked position) at an address, titled `prefix + name`.

    WHEN-TO-USE: To leave a durable, human-visible breadcrumb on an interesting address so the analyst can jump back to it from the IDA bookmark list. Reuses the existing slot if one already points at `addr` (so re-bookmarking the same address updates the title in place instead of consuming another slot).

    RETURNS: A BookmarkResult with `addr`, `ea`, the chosen `slot`, the final `title`, the `prefix`, and `ok`. On failure (all 1024 slots taken) `ok` is False and `error` explains why.

    PITFALL: There are only MAX_BOOKMARK_SLOTS (1024) slots in the whole database, shared with manually placed bookmarks; pass `prefix=""` only when you deliberately want a bare title with no `idaMCP:` namespace tag."""
    ea = parse_address(addr)
    title = f"{prefix}{name}"
    free_slot: int | None = None

    for slot in range(MAX_BOOKMARK_SLOTS):
        slot_ea = idc.get_bookmark(slot)
        if slot_ea == idc.BADADDR:
            if free_slot is None:
                free_slot = slot
            continue

        if slot_ea == ea:
            free_slot = slot
            break

    if free_slot is None:
        return {
            "addr": addr,
            "ea": hex(ea),
            "slot": None,
            "title": title,
            "prefix": prefix,
            "ok": False,
            "error": "No free bookmark slot",
        }

    idc.put_bookmark(ea, 0, 0, 0, free_slot, title)
    return {
        "addr": addr,
        "ea": hex(ea),
        "slot": free_slot,
        "title": title,
        "prefix": prefix,
        "ok": True,
    }


@safety("WRITE")
@title("Set Comments")
@tool
@idasync
def set_comments(
    items: Annotated[
        list[CommentOp] | CommentOp,
        "One {addr, comment} op or a list of them; each REPLACES the existing comment at that address.",
    ],
) -> list[CommentResult]:
    """WHAT: Overwrite the comment at one or more addresses in BOTH the disassembly view and the Hex-Rays decompiler view. Function-entry addresses get a repeatable function comment; other addresses get a line/pseudocode comment placed at the nearest mapped statement.

    WHEN-TO-USE: To record a finding directly on an instruction or function so it shows up in both IDA views. Prefer `append_comments` instead when you want to ADD a note without discarding what is already there.

    RETURNS: One CommentResult per input op, each carrying `addr`; ops that failed (bad address, no decompiler mapping, set rejected) additionally carry `error`. The list order matches the input order, so a missing `error` means success.

    PITFALL: This REPLACES, not appends — any prior comment at that address is lost. Decompiler placement is best-effort: if Hex-Rays is unavailable or the address has no eamap entry, the disassembly comment still succeeds and the op returns without an `error`."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        comment = item.get("comment", "")

        try:
            ea = parse_address(addr_str)

            if not idaapi.set_cmt(ea, comment, False):
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set disassembly comment at {hex(ea)}",
                    }
                )
                continue

            if not ida_hexrays.init_hexrays_plugin():
                results.append({"addr": addr_str})
                continue

            try:
                cfunc = decompile_checked(ea)
            except IDAError:
                results.append({"addr": addr_str})
                continue

            if ea == cfunc.entry_ea:
                idc.set_func_cmt(ea, comment, True)
                cfunc.refresh_func_ctext()
                results.append({"addr": addr_str})
                continue

            eamap = cfunc.get_eamap()
            if ea not in eamap:
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
                continue
            nearest_ea = eamap[ea][0].ea

            if cfunc.has_orphan_cmts():
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()

            tl = idaapi.treeloc_t()
            tl.ea = nearest_ea
            for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                tl.itp = itp
                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()
                cfunc.refresh_func_ctext()
                if not cfunc.has_orphan_cmts():
                    results.append({"addr": addr_str})
                    break
                cfunc.del_orphan_cmts()
                cfunc.save_user_cmts()
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set decompiler comment at {hex(ea)}",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


@safety("WRITE")
@title("Append Comments")
@tool
@idasync
def append_comments(
    items: Annotated[
        list[CommentAppendOp] | CommentAppendOp,
        "One {addr, comment, scope?, dedupe?} op or a list; appends each comment instead of replacing.",
    ],
) -> list[AppendCommentResult]:
    """WHAT: Append text to the existing comment at one or more addresses, joining with a newline, and (by default) skipping the write when that exact line is already present.

    WHEN-TO-USE: To accrete multiple notes on the same address across passes without clobbering earlier comments. Use this rather than `set_comments` whenever prior context must survive.

    RETURNS: One AppendCommentResult per op with `addr` and the resolved `scope` ("func" or "line"); successful writes carry `appended: True`, dedupe hits carry `skipped: True`, and failures carry `error`.

    PRO-TIP: `scope` defaults to "auto" — a function-entry address becomes a function comment, everything else becomes a line comment; force it with `scope="func"`/`scope="line"`. Set `dedupe: false` to allow the identical line to be appended again. Unlike `set_comments`, this does not write into the decompiler comment store, only the disassembly/function comment."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        comment = item.get("comment", "")
        scope = str(item.get("scope", "auto") or "auto").lower()
        dedupe = bool(item.get("dedupe", True))

        try:
            ea = parse_address(addr_str)
            if scope not in {"auto", "func", "line"}:
                results.append({"addr": addr_str, "error": f"Unsupported scope: {scope}"})
                continue

            fn = idaapi.get_func(ea)
            use_func_comment = scope == "func" or (
                scope == "auto" and fn is not None and fn.start_ea == ea
            )

            if use_func_comment:
                if fn is None:
                    results.append({"addr": addr_str, "error": f"No function found at {hex(ea)}"})
                    continue
                target_ea = fn.start_ea
                current = idc.get_func_cmt(target_ea, False) or ""
                new_comment, skipped = _append_comment_text(current, comment, dedupe=dedupe)
                if skipped:
                    results.append({"addr": addr_str, "scope": "func", "skipped": True})
                    continue
                if not idc.set_func_cmt(target_ea, new_comment, False):
                    results.append(
                        {
                            "addr": addr_str,
                            "error": f"Failed to set function comment at {hex(target_ea)}",
                        }
                    )
                    continue
                results.append({"addr": addr_str, "scope": "func", "appended": True})
                continue

            current = idaapi.get_cmt(ea, False) or ""
            new_comment, skipped = _append_comment_text(current, comment, dedupe=dedupe)
            if skipped:
                results.append({"addr": addr_str, "scope": "line", "skipped": True})
                continue
            if not idaapi.set_cmt(ea, new_comment, False):
                results.append(
                    {
                        "addr": addr_str,
                        "error": f"Failed to set disassembly comment at {hex(ea)}",
                    }
                )
                continue
            results.append({"addr": addr_str, "scope": "line", "appended": True})
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results


def _append_comment_text(current: str, new_text: str, *, dedupe: bool) -> tuple[str, bool]:
    normalized_new = new_text.strip()
    if dedupe and normalized_new:
        existing_entries = [line.strip() for line in current.splitlines()]
        if normalized_new in existing_entries:
            return current, True
    if not current:
        return new_text, False
    if not new_text:
        return current, False
    joiner = "" if current.endswith("\n") else "\n"
    return f"{current}{joiner}{new_text}", False


@safety("PATCH")
@title("Patch Assembly")
@tool
@idasync
def patch_asm(
    items: Annotated[
        list[AsmPatchOp] | AsmPatchOp,
        "One {addr, asm} op or a list; `asm` is one or more instructions separated by ';' assembled sequentially from `addr`.",
    ],
    confirm: Annotated[
        bool,
        "Explicit consent to write. With confirm=false (default) the call only "
        "PREVIEWS (original vs assembled bytes); set confirm=true AND dry_run=false to apply.",
    ] = False,
    dry_run: Annotated[
        bool,
        "When true (default) the call previews and writes nothing. Set false "
        "(with confirm=true) to actually patch.",
    ] = True,
) -> PatchAsmResponse:
    """Assemble instructions and overwrite the analysed program's code bytes, gated by consent (PATCH).

    WHAT: For each {addr, asm}, assembles the ';'-separated instructions with
    `idautils.Assemble` (which computes the bytes WITHOUT writing), accumulates
    the assembled bytes over the whole span, validates that every byte of the
    span is mapped, captures the current (original) bytes, and — only when the
    server patch gate is open AND confirm=true AND dry_run=false — writes the
    assembled bytes into the IDB at `addr`. Otherwise it returns a non-writing
    PREVIEW (original vs new) and touches nothing.

    WHEN-TO-USE: ONLY when the user has explicitly asked to patch the binary's
    code (e.g. NOP out a check, redirect a branch). Patching is never part of
    analysis; the default previews so that understanding a binary never mutates
    it (axis-7 never-patch-without-consent rule).

    RETURNS: A PatchAsmResponse {applied, dry_run, allowed, reason, consent?,
    results[]}. Each result is {addr, size, original, new, applied} on success or
    {addr, error}. When the assembled bytes are SHORTER than the original
    instruction(s) at `addr`, the result also carries `tail_orphan_bytes: N`
    warning that N stale bytes remain (they are NOT auto-padded). `allowed`
    reflects the server gate (IDA_MCP_ALLOW_PATCH / set_patch_allowed); `reason`
    explains any withholding.

    PITFALL: Assembly is not auto-aligned to instruction boundaries — a shorter
    replacement leaves trailing original bytes (reported via `tail_orphan_bytes`),
    a longer one overruns the next instruction. Assembly syntax must satisfy
    `idautils.Assemble`. Use revert_patch to undo and list_patches to review."""
    if isinstance(items, dict):
        items = [items]

    will_write, reason = patch_decision(confirm, dry_run)
    results: list[dict] = []
    any_applied = False

    for item in items:
        addr_str = item.get("addr") if isinstance(item, dict) else None
        instructions = item.get("asm", "") if isinstance(item, dict) else ""

        try:
            ea = parse_address(addr_str)

            # Decode the original item length at the start ea so we can detect a
            # shorter replacement that would leave stale tail bytes behind.
            try:
                orig_item_size = idc.get_item_size(ea)
            except Exception:
                orig_item_size = 0

            # Assemble each ';'-separated instruction WITHOUT writing, advancing a
            # cursor so each instruction is assembled at the address it lands on.
            assembled = bytearray()
            cursor = ea
            assemble_error: str | None = None
            for assemble in instructions.split(";"):
                assemble = assemble.strip()
                if not assemble:
                    continue
                check_assemble, bytes_to_patch = idautils.Assemble(cursor, assemble)
                if not check_assemble:
                    assemble_error = f"Failed to assemble at {hex(cursor)}: {assemble}"
                    break
                assembled.extend(bytes_to_patch)
                cursor += len(bytes_to_patch)

            if assemble_error is not None:
                results.append({"addr": addr_str, "error": assemble_error})
                continue

            size = len(assembled)
            if size == 0:
                results.append({"addr": addr_str, "error": "no instructions assembled"})
                continue

            mapped, bad_ea = span_status(ea, size)
            if not mapped:
                results.append(
                    {
                        "addr": addr_str,
                        "error": (
                            f"Address span not fully mapped (first unmapped byte at "
                            f"{hex(bad_ea)} in {hex(ea)}..{hex(ea + size)})"
                        ),
                    }
                )
                continue

            entry: dict = {
                "addr": addr_str,
                "size": size,
                "original": capture_original(ea, size),
                "new": bytes(assembled).hex(),
                "applied": False,
            }
            if orig_item_size > size:
                entry["tail_orphan_bytes"] = orig_item_size - size
            if will_write:
                ida_bytes.patch_bytes(ea, bytes(assembled))
                entry["applied"] = True
                any_applied = True
            results.append(entry)
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    response: dict = {
        "applied": any_applied,
        "dry_run": dry_run,
        "allowed": patching_allowed(),
        "reason": reason,
        "results": results,
    }
    if not will_write:
        response["consent"] = withheld_hint(reason)
    return response


def rename_at_ea(
    ea: int,
    new_name: str,
    *,
    allow_overwrite: bool = False,
    dry_run: bool = False,
) -> tuple[bool, str | None]:
    """Rename at address with detailed error reporting."""
    conflict_ea = idaapi.get_name_ea(idaapi.BADADDR, new_name)
    if (
        conflict_ea != idaapi.BADADDR
        and conflict_ea != ea
        and not allow_overwrite
    ):
        return (
            False,
            f"can't rename at {hex(ea)} as {new_name!r}: name already used at {hex(conflict_ea)}",
        )

    if dry_run:
        return True, None

    flags = idaapi.SN_CHECK
    if allow_overwrite:
        flags = idaapi.SN_CHECK | int(getattr(idaapi, "SN_FORCE", 0))
    ok = idaapi.set_name(ea, new_name, flags)
    if not ok:
        return (
            False,
            f"Rename failed at {hex(ea)}: IDA rejected name {new_name!r} "
            "(invalid identifier or internal conflict)",
        )
    return True, None


@safety("WRITE")
@title("Rename Symbols (Batch)")
@tool
@idasync
def rename(
    batch: Annotated[
        RenameBatch,
        "Batch with any of func/data(global,globals)/local/stack item lists plus options dry_run, allow_overwrite, stop_on_error; at least one category required.",
    ],
) -> RenameResult:
    """WHAT: Rename functions, globals/data, decompiler local variables, and stack/frame variables in one transactional batch, processing categories in order func -> data -> local -> stack.

    WHEN-TO-USE: To apply a set of recovered names at once (e.g. promoting glossary names onto sub_xxxx noise). Run first with `dry_run: true` to validate every name (and detect collisions) without touching the database, then re-run to apply.

    RETURNS: A RenameResult with a per-category list of per-item outcomes (each `{addr/func_addr, old, new/name, error?, dry_run?, dir?}`) plus a `summary` (`total`, `ok`, `failed`, `stopped`, and echoed flags). Newly named functions that had no prior user name are also filed under the IDA `/vibe/` function folder (reported as `dir: "vibe"`).

    PRO-TIP: Name collisions are rejected unless `allow_overwrite: true`; with `stop_on_error: true` the batch halts at the first failure and `summary.stopped_at` names the category. Local and stack renames require Hex-Rays and a function frame respectively, and argument/special frame members cannot be renamed."""

    stop_on_error = bool(batch.get("stop_on_error", False))
    dry_run = bool(batch.get("dry_run", False))
    allow_overwrite = bool(batch.get("allow_overwrite", False))

    def _normalize_items(items):
        if items is None:
            return []
        if isinstance(items, dict):
            return [items]
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
        return []

    def _has_user_name(ea: int) -> bool:
        flags = idaapi.get_flags(ea)
        checker = getattr(idaapi, "has_user_name", None)
        if checker is not None:
            return checker(flags)
        try:
            import ida_name

            checker = getattr(ida_name, "has_user_name", None)
            if checker is not None:
                return checker(flags)
        except Exception:
            pass
        return False

    def _set_name_checked(ea: int, new_name: str) -> tuple[bool, str | None]:
        return rename_at_ea(
            ea,
            new_name,
            allow_overwrite=allow_overwrite,
            dry_run=dry_run,
        )

    def _place_func_in_vibe_dir(ea: int) -> tuple[bool, str | None]:
        if dry_run:
            return True, None

        tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        if tree is None:
            return False, "Function dirtree not available"
        if not tree.load():
            return False, "Failed to load function dirtree"

        vibe_path = "/vibe/"
        if not tree.isdir(vibe_path):
            err = tree.mkdir(vibe_path)
            if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                return False, f"mkdir failed: {err}"

        old_cwd = tree.getcwd()
        try:
            if tree.chdir(vibe_path) != ida_dirtree.DTE_OK:
                return False, "Failed to chdir to vibe"
            err = tree.link(ea)
            if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                return False, f"link failed: {err}"
            if not tree.save():
                return False, "Failed to save function dirtree"
        finally:
            if old_cwd:
                tree.chdir(old_cwd)

        return True, None

    def _rename_funcs(items: list[FunctionRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                addr_text = item.get("addr") or item.get("func_addr") or item.get("func")
                new_name = item.get("name") or item.get("new") or item.get("new_name")
                if not addr_text or not new_name:
                    result = {
                        "addr": addr_text,
                        "name": new_name,
                        "error": "Function rename requires addr + name",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                ea = parse_address(addr_text)
                func = idaapi.get_func(ea)
                if not func:
                    result = {
                        "addr": addr_text,
                        "name": new_name,
                        "error": "Function not found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                old_name = idaapi.get_name(func.start_ea) or None
                had_user_name = _has_user_name(func.start_ea)
                success, error = _set_name_checked(func.start_ea, str(new_name))

                placed, place_error = None, None
                if success and not had_user_name:
                    placed, place_error = _place_func_in_vibe_dir(func.start_ea)
                if success and not dry_run:
                    refresh_decompiler_ctext(func.start_ea)

                result = {
                    "addr": addr_text,
                    "old": old_name,
                    "name": str(new_name),
                }
                if error:
                    result["error"] = error
                if success and placed:
                    result["dir"] = "vibe"
                if place_error and success:
                    result["dir_error"] = place_error
                if dry_run:
                    result["dry_run"] = True
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"addr": item.get("addr"), "error": str(e)})
                if stop_on_error:
                    halted = True
                    break
        return results, halted

    def _rename_globals(items: list[GlobalRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                addr_text = item.get("addr")
                old_name = item.get("old") or item.get("old_name")
                new_name = item.get("new") or item.get("new_name")

                # Backward-compatible forms:
                # 1) {addr, name} => rename by address
                # 2) {name, new_name} => old=name, new=new_name
                if new_name is None and addr_text is not None and item.get("name"):
                    new_name = item.get("name")
                if old_name is None and new_name is not None and item.get("name") and not addr_text:
                    old_name = item.get("name")

                if not new_name:
                    result = {
                        "old": old_name,
                        "new": None,
                        "error": "Global rename requires target and new name",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                ea = idaapi.BADADDR
                if addr_text:
                    ea = parse_address(str(addr_text))
                    old_name = old_name or (idaapi.get_name(ea) or None)
                elif old_name:
                    ea = idaapi.get_name_ea(idaapi.BADADDR, str(old_name))

                if ea == idaapi.BADADDR:
                    result = {
                        "old": old_name,
                        "new": str(new_name),
                        "error": f"Global '{old_name}' not found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                success, error = _set_name_checked(ea, str(new_name))
                result = {
                    "addr": hex(ea),
                    "old": old_name,
                    "new": str(new_name),
                }
                if error:
                    result["error"] = error
                if dry_run:
                    result["dry_run"] = True
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"old": item.get("old"), "error": str(e)})
                if stop_on_error:
                    halted = True
                    break
        return results, halted

    def _rename_locals(items: list[LocalRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                func_addr = item.get("func_addr") or item.get("func")
                old_name = item.get("old") or item.get("name")
                new_name = item.get("new") or item.get("new_name")
                if not func_addr or not old_name or not new_name:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "Local rename requires func_addr + old + new",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                func = idaapi.get_func(parse_address(func_addr))
                if not func:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "No function found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                success = True
                error = None
                if not dry_run:
                    if not ida_hexrays.init_hexrays_plugin():
                        success = False
                        error = (
                            "Hex-Rays decompiler is not available "
                            "(required for local variable rename)"
                        )
                    else:
                        success = ida_hexrays.rename_lvar(
                            func.start_ea, old_name, new_name
                        )
                        if success:
                            refresh_decompiler_ctext(func.start_ea)
                        elif not hexrays_local_var_exists(func.start_ea, old_name):
                            error = (
                                f"Local variable {old_name!r} not found in function at "
                                f"{hex(func.start_ea)}"
                            )
                        else:
                            error = (
                                f"Rename failed: could not rename local {old_name!r} "
                                f"to {new_name!r}"
                            )
                if not success:
                    error = error or (
                        f"Rename failed: could not rename local {old_name!r} to {new_name!r}"
                    )

                result = {
                    "func_addr": func_addr,
                    "old": old_name,
                    "new": new_name,
                }
                if error:
                    result["error"] = error
                if dry_run:
                    result["dry_run"] = True
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), "error": str(e)})
                if stop_on_error:
                    halted = True
                    break
        return results, halted

    def _rename_stack(items: list[StackRename]) -> tuple[list[dict], bool]:
        results: list[dict] = []
        halted = False
        for item in items:
            try:
                func_addr = item.get("func_addr") or item.get("func")
                old_name = item.get("old") or item.get("name")
                new_name = item.get("new") or item.get("new_name")
                if not func_addr or not old_name or not new_name:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "Stack rename requires func_addr + old + new",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                func = idaapi.get_func(parse_address(func_addr))
                if not func:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "No function found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "No frame",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                idx, udm = tinfo_get_udm(frame_tif, old_name)
                if not udm:
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": f"'{old_name}' not found",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                tid = frame_tif.get_udm_tid(idx)
                if ida_frame.is_special_frame_member(tid):
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "Special frame member",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8
                if ida_frame.is_funcarg_off(func, offset):
                    result = {
                        "func_addr": func_addr,
                        "old": old_name,
                        "new": new_name,
                        "error": "Argument member",
                    }
                    results.append(result)
                    if stop_on_error:
                        halted = True
                        break
                    continue

                success = True
                error = None
                if not dry_run:
                    _, conflict_udm = tinfo_get_udm(frame_tif, new_name)
                    if conflict_udm and new_name != old_name:
                        success = False
                        error = f"Stack variable name {new_name!r} already exists"
                    else:
                        sval = ida_frame.soff_to_fpoff(func, offset)
                        success = ida_frame.define_stkvar(func, new_name, sval, udm.type)
                        if not success:
                            error = (
                                f"Rename failed: could not rename stack variable "
                                f"{old_name!r} to {new_name!r} in function at "
                                f"{hex(func.start_ea)}"
                            )
                if not success:
                    error = error or (
                        f"Rename failed: could not rename stack variable {old_name!r} "
                        f"to {new_name!r} in function at {hex(func.start_ea)}"
                    )

                result = {
                    "func_addr": func_addr,
                    "old": old_name,
                    "new": new_name,
                }
                if error:
                    result["error"] = error
                if dry_run:
                    result["dry_run"] = True
                results.append(result)
                if not success and stop_on_error:
                    halted = True
                    break
            except Exception as e:
                results.append({"func_addr": item.get("func_addr"), "error": str(e)})
                if stop_on_error:
                    halted = True
                    break
        return results, halted

    data_items = []
    data_items.extend(_normalize_items(batch.get("data")))
    data_items.extend(_normalize_items(batch.get("global")))
    data_items.extend(_normalize_items(batch.get("globals")))

    requested = {
        "func": "func" in batch,
        "data": any(key in batch for key in ("data", "global", "globals")),
        "local": "local" in batch,
        "stack": "stack" in batch,
        "global_alias": any(key in batch for key in ("global", "globals")),
    }

    result: dict = {}
    stopped = False
    stopped_at = None

    if requested["func"]:
        result["func"], halted = _rename_funcs(_normalize_items(batch.get("func")))
        if halted:
            stopped = True
            stopped_at = "func"

    if requested["data"] and not stopped:
        result["data"], halted = _rename_globals(data_items)
        if requested["global_alias"]:
            result["global"] = list(result["data"])
        if halted:
            stopped = True
            stopped_at = "data"

    if requested["local"] and not stopped:
        result["local"], halted = _rename_locals(_normalize_items(batch.get("local")))
        if halted:
            stopped = True
            stopped_at = "local"

    if requested["stack"] and not stopped:
        result["stack"], halted = _rename_stack(_normalize_items(batch.get("stack")))
        if halted:
            stopped = True
            stopped_at = "stack"

    total = 0
    ok = 0
    failed = 0
    for key in ("func", "data", "local", "stack"):
        for item in result.get(key, []):
            total += 1
            if "error" not in item:
                ok += 1
            else:
                failed += 1

    summary: dict = {
        "total": total,
        "ok": ok,
        "failed": failed,
        "stopped": stopped,
    }
    if dry_run:
        summary["dry_run"] = True
    if allow_overwrite:
        summary["allow_overwrite"] = True
    if stop_on_error:
        summary["stop_on_error"] = True
    if stopped:
        summary["stopped_at"] = stopped_at
    result["summary"] = summary
    return result


@safety("DESTRUCTIVE")
@title("Define Functions")
@tool
@idasync
def define_func(
    items: Annotated[
        list[DefineOp] | DefineOp,
        "One {addr, end?} op or a list; `addr` is the function start, optional `end` is an exclusive end EA (omit to let IDA infer the bounds).",
    ],
) -> list[DefineResult]:
    """WHAT: Create a function at one or more start addresses, letting IDA auto-detect the end unless an explicit `end` is supplied.

    WHEN-TO-USE: When the auto-analysis missed a function (e.g. code reached only by an indirect call, or bytes that were never defined as code) and you need it materialized so it can be decompiled, renamed, or cross-referenced.

    RETURNS: One DefineResult per op with `addr` and, on success, the resolved `start`/`end`; ops that failed carry `error` ("Function already exists at this address", or "define_func failed" when IDA refused the bounds).

    PITFALL: The target bytes must already be (or be analyzable as) code — run `define_code` first on raw data. Supplying a too-large `end` can swallow a neighboring function; omit `end` to trust IDA's inference. This invalidates the strings cache as a side effect."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        end_str = item.get("end", "")

        try:
            start_ea = parse_address(addr_str)
            end_ea = parse_address(end_str) if end_str else idaapi.BADADDR

            # Check if already a function
            existing = idaapi.get_func(start_ea)
            if existing and existing.start_ea == start_ea:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "Function already exists at this address",
                    }
                )
                continue

            success = ida_funcs.add_func(start_ea, end_ea)
            if success:
                func = idaapi.get_func(start_ea)
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(func.start_ea),
                        "end": hex(func.end_ea),
                    }
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "define_func failed",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    invalidate_strings_cache()
    return results


@safety("DESTRUCTIVE")
@title("Define Code")
@tool
@idasync
def define_code(
    items: Annotated[
        list[DefineOp] | DefineOp,
        "One {addr} op or a list; `addr` is where a single instruction is decoded from raw bytes.",
    ],
) -> list[DefineResult]:
    """WHAT: Decode the bytes at one or more addresses into a single CPU instruction each (the GUI 'C' / make-code action), converting raw/undefined bytes to code.

    WHEN-TO-USE: As the step before `define_func` when a region is sitting as undefined bytes or data and must first be turned into instructions, or to fix a spot the analyzer left as data.

    RETURNS: One DefineResult per op with `addr`, `ea`, and the decoded instruction `length` in bytes on success; failures carry `error` ("Failed to create instruction") when the bytes do not decode at that address.

    PITFALL: This defines exactly ONE instruction per op, not a whole run — to convert a region, walk forward by the returned `length`. If the address overlaps existing code or undefinable data the op fails. Invalidates the strings cache as a side effect."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")

        try:
            ea = parse_address(addr_str)
            length = ida_ua.create_insn(ea)
            if length > 0:
                results.append(
                    {"addr": addr_str, "ea": hex(ea), "length": length}
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "ea": hex(ea),
                        "error": "Failed to create instruction",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    invalidate_strings_cache()
    return results


@safety("DESTRUCTIVE")
@title("Undefine Items")
@tool
@idasync
def undefine(
    items: Annotated[
        list[UndefineOp] | UndefineOp,
        "One {addr, end?|size?} op or a list; undefines from `addr` for `end-addr` bytes, else `size` bytes, else a single item.",
    ],
) -> list[DefineResult]:
    """WHAT: Undefine code/data items at one or more addresses, converting them back to raw undefined bytes over a span derived from `end`, `size`, or a single item by default.

    WHEN-TO-USE: To clear a mis-analyzed region (wrong instruction boundaries, a bogus array, data the analyzer mistook for code) so it can be re-defined cleanly with `define_code` / `define_func` / `make_data`.

    RETURNS: One DefineResult per op with `addr`, `start`, and the actual `size` undefined on success; failures carry `error` ("undefine failed").

    PITFALL: Uses DELIT_EXPAND, so undefining can cascade into adjacent items whose definition depended on this one — undefine the minimal span you need. With neither `end` nor `size` only one item is removed. Invalidates the strings cache as a side effect."""
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        end_str = item.get("end", "")
        size = item.get("size", 0)

        try:
            start_ea = parse_address(addr_str)

            # Determine size from end address or explicit size
            if end_str:
                end_ea = parse_address(end_str)
                nbytes = end_ea - start_ea
            elif size:
                nbytes = size
            else:
                # Default: undefine single item
                nbytes = 1

            success = ida_bytes.del_items(start_ea, ida_bytes.DELIT_EXPAND, nbytes)
            if success:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "size": nbytes,
                    }
                )
            else:
                results.append(
                    {
                        "addr": addr_str,
                        "start": hex(start_ea),
                        "error": "undefine failed",
                    }
                )
        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    invalidate_strings_cache()
    return results


# ============================================================================
# Hex-Rays + operand-typing operations (the "last 20% polish" tools)
# ============================================================================


class ForceRecompileOp(TypedDict, total=False):
    addr: str  # function entry, or "*" / omitted to recompile every function


class ForceRecompileResult(TypedDict, total=False):
    addr: str
    name: str
    ok: bool
    error: str


class ForceRecompileBatchSummary(TypedDict):
    total: int
    ok: int
    failed: int
    all: bool


class ForceRecompileSummary(TypedDict):
    summary: ForceRecompileBatchSummary
    results: list[ForceRecompileResult]


@safety("WRITE")
@title("Force Hex-Rays Recompile")
@tool
@idasync
def force_recompile(
    items: Annotated[
        list[ForceRecompileOp] | ForceRecompileOp,
        "List of {addr: function-entry-EA} ops, or a single op. Omit / pass None / pass an empty list to invalidate EVERY function.",
    ] = None,
) -> ForceRecompileSummary:
    """WHAT: Invalidate the Hex-Rays decompiler cache for specific functions (or all of them) so the next `decompile` regenerates fresh pseudocode instead of returning a stale cached view. Does not change any database content.

    WHEN-TO-USE: Right after `set_type`, `rename` (especially of locals), `set_op_type`, or `make_data` — those edits do not always auto-dirty dependent functions, so the decompiler can otherwise keep serving outdated output.

    RETURNS: A ForceRecompileSummary with `summary` (`total`, `ok`, `failed`, `all`) and a `results` list of per-function `{addr, name, ok, error?}`.

    PRO-TIP: Omitting `items` (or passing an empty list) dirties every function — cheap but broad; pass the specific entry EAs you just edited to keep it targeted. Addresses are resolved to their enclosing function start, so any EA inside a function works."""
    targets: list[int] = []
    invalidate_all = False

    if items is None:
        invalidate_all = True
    elif isinstance(items, dict):
        items = [items]
    elif isinstance(items, list) and len(items) == 0:
        invalidate_all = True

    if invalidate_all:
        targets = list(idautils.Functions())
    else:
        for item in items or []:
            addr_str = item.get("addr") if isinstance(item, dict) else None
            if not addr_str:
                continue
            try:
                ea = parse_address(addr_str)
                func = ida_funcs.get_func(ea)
                if func is not None:
                    targets.append(func.start_ea)
            except Exception:
                pass

    results: list[ForceRecompileResult] = []
    for ea in targets:
        try:
            ida_hexrays.mark_cfunc_dirty(ea)
            results.append({
                "addr": hex(ea),
                "name": ida_funcs.get_func_name(ea) or "",
                "ok": True,
            })
        except Exception as e:
            results.append({"addr": hex(ea), "ok": False, "error": str(e)})

    return {
        "summary": {
            "total": len(results),
            "ok": sum(1 for r in results if r.get("ok")),
            "failed": sum(1 for r in results if not r.get("ok")),
            "all": invalidate_all,
        },
        "results": results,
    }


class SetOpTypeOp(TypedDict, total=False):
    addr: str  # instruction EA
    op_n: int  # operand index (0 = first operand)
    kind: str  # "stroff" | "offset" | "hex" | "dec" | "char" | "binary" | "stkvar"
    struct: NotRequired[str]  # struct name (required for kind="stroff")
    delta: NotRequired[int]  # offset within struct (default 0)
    target_addr: NotRequired[str]  # for kind="offset", the symbol the operand references


class SetOpTypeResult(TypedDict, total=False):
    addr: str
    op_n: int
    kind: str
    ok: bool
    error: str


_OP_FORMAT_FLAGS = {
    "hex": ida_bytes.FF_0NUMH,
    "dec": ida_bytes.FF_0NUMD,
    "char": ida_bytes.FF_0CHAR,
    "binary": ida_bytes.FF_0NUMB,
    "octal": ida_bytes.FF_0NUMO,
}


@safety("WRITE")
@title("Set Operand Type")
@tool
@idasync
def set_op_type(
    items: Annotated[
        list[SetOpTypeOp] | SetOpTypeOp,
        "One operand-typing op or a list. Each {addr, op_n, kind, struct?, delta?, target_addr?}; GUI 'Y'/'O'/'#' equivalent.",
    ],
) -> list[SetOpTypeResult]:
    """WHAT: Reinterpret a chosen operand of an instruction — as a struct-field reference, an absolute offset/pointer, a stack variable, or a specific numeric radix (the GUI 'Y' / 'O' / '#' actions).

    WHEN-TO-USE: When the decompiler renders an operand awkwardly — e.g. shows `nearby_global + 0x10` instead of a struct member, displays a raw constant that is really an address, or formats a flag value in decimal you want as hex. Tagging the operand pushes Hex-Rays toward the right expression.

    RETURNS: One SetOpTypeResult per op with `addr`, `op_n`, `kind`, and `ok`; ops that fail validation or the underlying IDA call carry `error` (e.g. missing `struct`, struct-not-found, unknown `kind`).

    PRO-TIP: `kind` values — `"stroff"` (needs `struct`, optional `delta`), `"offset"` (optional `target_addr` for the referenced symbol), `"stkvar"` (function-local), and the numeric formats `"hex"|"dec"|"char"|"binary"|"octal"`. `op_n` is 0-based (0 = first operand). Follow with `force_recompile` on the enclosing function so the pseudocode actually reflects the change."""
    if isinstance(items, dict):
        items = [items]

    results: list[SetOpTypeResult] = []
    for item in items:
        addr_str = item.get("addr", "")
        op_n = int(item.get("op_n", 0))
        kind = str(item.get("kind", "")).strip().lower()

        try:
            ea = parse_address(addr_str)
        except Exception as e:
            results.append({"addr": addr_str, "op_n": op_n, "kind": kind, "ok": False, "error": str(e)})
            continue

        ok = False
        err = None
        try:
            if kind == "stroff":
                struct_name = str(item.get("struct", "")).strip()
                if not struct_name:
                    err = "struct name required for kind='stroff'"
                else:
                    delta = int(item.get("delta", 0))
                    # IDA 9.x: structs live in the local type library; resolve
                    # via tinfo_t.get_named_type and then get_tid.
                    til = ida_typeinf.get_idati()
                    sti = ida_typeinf.tinfo_t()
                    if not sti.get_named_type(til, struct_name):
                        err = f"struct not found: {struct_name}"
                    else:
                        tid = sti.get_tid()
                        if tid == idaapi.BADADDR:
                            err = f"struct {struct_name} has no tid"
                        else:
                            path = idaapi.tid_array(1)
                            path[0] = tid
                            ok = bool(ida_bytes.op_stroff(ea, op_n, path.cast(), 1, delta))
            elif kind == "offset":
                target_str = str(item.get("target_addr", "")).strip()
                if target_str:
                    target_ea = parse_address(target_str)
                    ok = bool(idc.op_plain_offset(ea, op_n, target_ea))
                else:
                    ok = bool(idc.op_plain_offset(ea, op_n, 0))
            elif kind == "stkvar":
                ok = bool(idc.op_stkvar(ea, op_n))
            elif kind in _OP_FORMAT_FLAGS:
                flag = _OP_FORMAT_FLAGS[kind]
                ok = bool(ida_bytes.set_op_type(ea, flag, op_n))
            else:
                err = f"unknown kind: {kind!r} (expected stroff/offset/stkvar/hex/dec/char/binary/octal)"
        except Exception as e:
            err = str(e)

        result: SetOpTypeResult = {"addr": addr_str, "op_n": op_n, "kind": kind, "ok": ok}
        if err is not None and not ok:
            result["error"] = err
        results.append(result)

    return results


class MakeDataOp(TypedDict, total=False):
    addr: str
    type: str  # full C declaration, e.g. "ISP_SNS_STATE_S * g_pastImx290[4]"
    name: NotRequired[str]  # optional rename
    delete_existing: NotRequired[bool]  # default True


class MakeDataResult(TypedDict, total=False):
    addr: str
    name: str
    type: str
    size: int
    ok: bool
    error: str


@safety("DESTRUCTIVE")
@title("Make Typed Data")
@tool
@idasync
def make_data(
    items: Annotated[
        list[MakeDataOp] | MakeDataOp,
        "One {addr, type, name?, delete_existing?} op or a list. `type` is a full C declaration; replaces existing items at `addr` with a fresh typed symbol.",
    ],
) -> list[MakeDataResult]:
    """WHAT: Create a typed data symbol at an address — applies the type, deletes the underlying byte items so the size is correct, re-applies the type, and optionally renames the symbol.

    WHEN-TO-USE: To harden a data boundary the decompiler is currently expressing through a neighboring global plus offset (e.g. a real array that IDA split). Prefer this over `set_type` when the existing byte items are the wrong size — `set_type` alone leaves them untouched, this re-lays them.

    RETURNS: One MakeDataResult per op with `addr`, the resolved `name`, the applied `type`, the `size` in bytes, and `ok`; failures carry `error` (bad address, "type declaration is required", or "SetType rejected declaration").

    PRO-TIP: `type` is a FULL C declaration with a placeholder name, e.g. `"ISP_SNS_STATE_S * g_pastImx290[4]"` — IDA parses it via SetType (a trailing `;` is added if missing). It clears all cached cfuncs so subsequent `decompile` calls are fresh. Set `delete_existing: false` only when you trust the current item layout already matches the type."""
    if isinstance(items, dict):
        items = [items]

    results: list[MakeDataResult] = []
    for item in items:
        addr_str = item.get("addr", "")
        type_decl = str(item.get("type", "")).strip()
        name = str(item.get("name", "")).strip()
        delete_existing = bool(item.get("delete_existing", True))

        try:
            ea = parse_address(addr_str)
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})
            continue

        if not type_decl:
            results.append({"addr": addr_str, "ok": False, "error": "type declaration is required"})
            continue

        # Ensure the declaration has a trailing semicolon for SetType.
        decl = type_decl if type_decl.endswith(";") else type_decl + ";"

        try:
            # Apply the type (this also tells us the size).
            apply_ok = idc.SetType(ea, decl)
            if not apply_ok:
                results.append({"addr": addr_str, "ok": False, "error": f"SetType rejected declaration: {decl!r}"})
                continue

            # Compute size from the now-applied type.
            tif = ida_typeinf.tinfo_t()
            try:
                ok_t = ida_typeinf.guess_tinfo(tif, ea)
            except Exception:
                ok_t = False
            size = tif.get_size() if ok_t else 0

            if delete_existing and size > 0:
                ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, size)
                # Re-apply after del_items (it can clobber the type binding).
                idc.SetType(ea, decl)

            if name:
                ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)

            # Mark all dependent decompiles dirty so subsequent decompile() gets fresh output.
            ida_hexrays.clear_cached_cfuncs()

            results.append({
                "addr": addr_str,
                "name": name or (ida_name.get_name(ea) or ""),
                "type": idc.get_type(ea) or "",
                "size": size,
                "ok": True,
            })
        except Exception as e:
            results.append({"addr": addr_str, "ok": False, "error": str(e)})

    return results
