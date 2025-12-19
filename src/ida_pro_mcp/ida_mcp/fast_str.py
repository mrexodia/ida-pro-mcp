from typing import Optional

import ida_nalt
import ida_strlist
import idautils

from .utils import String

_strings_cache: Optional[list[dict]] = None
_strings_cache_stamp: Optional[tuple[int, int]] = None
_strings_dump: str = ""
_strings_map: dict[str, list[int]] = {}
_strings_core: Optional[list[String]] = None
_DELIM: str = "\x00\x01\xFF\xFE"


def _current_stamp() -> tuple[int, int]:
    try:
        str_qty = ida_strlist.get_strlist_qty()
    except Exception:
        str_qty = 0

    try:
        open_count = ida_nalt.get_idb_nopens()
    except Exception:
        open_count = 0

    return (str_qty, open_count)


def _rebuild_cache() -> None:
    global _strings_cache, _strings_cache_stamp, _strings_dump, _strings_map, _strings_core

    _strings_cache = []
    _strings_map = {}
    _strings_core = None

    for item in idautils.Strings():
        if item is None:
            continue
        try:
            string = str(item)
            if not string:
                continue
            string_lower = string.lower()
            idx = len(_strings_cache)
            _strings_cache.append(
                {
                    "addr": hex(item.ea),
                    "length": item.length,
                    "string": string,
                    "string_lower": string_lower,
                    "type": item.strtype,
                }
            )
            if string_lower not in _strings_map:
                _strings_map[string_lower] = []
            _strings_map[string_lower].append(idx)
        except Exception:
            continue

    if _strings_map:
        _strings_dump = _DELIM + _DELIM.join(_strings_map.keys()) + _DELIM
    else:
        _strings_dump = _DELIM

    _strings_cache_stamp = _current_stamp()


def _ensure_cache() -> None:
    global _strings_cache_stamp
    stamp = _current_stamp()
    if _strings_cache is None or _strings_cache_stamp != stamp:
        _rebuild_cache()


def get_entries() -> list[dict]:
    _ensure_cache()
    return _strings_cache


def get_core_strings() -> list[String]:
    global _strings_core
    _ensure_cache()
    if _strings_core is None:
        _strings_core = [
            String(addr=s["addr"], length=s["length"], string=s["string"])
            for s in _strings_cache
        ]
    return _strings_core


def _has_regex_meta(pattern: str) -> bool:
    escape = False
    for ch in pattern:
        if escape:
            escape = False
            continue
        if ch == "\\":
            return True
        if ch in ".^$*+?{}[]|()":
            return True
    return False


def _literal_runs(pattern: str) -> list[str]:
    runs: list[str] = []
    current = ""
    escape = False
    for ch in pattern:
        if escape:
            current += ch
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch in ".^$*+?{}[]|()":
            if current:
                runs.append(current)
                current = ""
            continue
        current += ch
    if current:
        runs.append(current)
    return runs


def _find_by_substring(pattern_lower: str, limit: int, offset: int) -> tuple[list[int], bool]:
    results: list[int] = []
    skipped = 0
    more = False
    seen = set()

    pos = 0
    while True:
        pos = _strings_dump.find(pattern_lower, pos)
        if pos == -1:
            break
        start = _strings_dump.rfind(_DELIM, 0, pos)
        end = _strings_dump.find(_DELIM, pos)
        pos += 1
        if start == -1 or end == -1 or end <= start:
            continue
        start += len(_DELIM)
        matched_str = _strings_dump[start:end]
        if matched_str in seen:
            continue
        seen.add(matched_str)
        indices = _strings_map.get(matched_str, [])
        for idx in indices:
            if skipped < offset:
                skipped += 1
                continue
            results.append(idx)
            if len(results) >= limit:
                more = True
                break
        if more:
            break
    return results, more


def search_indices(pattern: str, limit: int, offset: int) -> tuple[list[int], bool]:
    import re

    _ensure_cache()

    if pattern == "":
        return [], False

    pattern_lower = pattern.lower()

    if pattern_lower in _strings_map:
        indices = _strings_map[pattern_lower]
        results: list[int] = []
        more = False
        for i, idx in enumerate(indices):
            if i < offset:
                continue
            results.append(idx)
            if len(results) >= limit:
                more = i + 1 < len(indices)
                break
        return results, more

    if not _has_regex_meta(pattern):
        return _find_by_substring(pattern_lower, limit, offset)

    runs = _literal_runs(pattern)
    runs = [r for r in runs if len(r) >= 5]
    if runs:
        anchor = max(runs, key=len).lower()
        regex = re.compile(pattern, re.IGNORECASE)
        results: list[int] = []
        skipped = 0
        more = False
        seen = set()
        pos = 0
        while True:
            pos = _strings_dump.find(anchor, pos)
            if pos == -1:
                break
            start = _strings_dump.rfind(_DELIM, 0, pos)
            end = _strings_dump.find(_DELIM, pos)
            pos += 1
            if start == -1 or end == -1 or end <= start:
                continue
            start += len(_DELIM)
            matched_str = _strings_dump[start:end]
            if matched_str in seen:
                continue
            seen.add(matched_str)
            if regex.search(matched_str) is None:
                continue
            indices = _strings_map.get(matched_str, [])
            for idx in indices:
                if skipped < offset:
                    skipped += 1
                    continue
                results.append(idx)
                if len(results) >= limit:
                    more = True
                    break
            if more:
                break
        return results, more

    escaped = re.escape(pattern_lower)
    delim_escaped = re.escape(_DELIM)
    regex = re.compile(
        f"{delim_escaped}([^\\x00]*?{escaped}[^\\x00]*?)(?={delim_escaped})",
        re.IGNORECASE,
    )

    results = []
    skipped = 0
    more = False

    for m in regex.finditer(_strings_dump):
        matched_str = m.group(1)
        indices = _strings_map.get(matched_str, [])
        for idx in indices:
            if skipped < offset:
                skipped += 1
                continue
            results.append(idx)
            if len(results) >= limit:
                more = True
                break
        if more:
            break

    return results, more
