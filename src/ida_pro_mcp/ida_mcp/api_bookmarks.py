"""Bookmarks Management - CRUD operations for IDA bookmarks via MCP.

This module provides tools to manage IDA bookmarks programmatically including:
- Listing bookmarks with optional filtering
- Adding new bookmarks with descriptions
- Removing bookmarks
- Bookmark folders (IDA 7.6+)
- Navigation to bookmarked locations

IDA API: ida_moves.bookmarks_t
"""

from typing import Annotated, NotRequired, TypedDict

import ida_kernwin
import ida_moves
import idaapi

from .rpc import tool
from .sync import idasync
from .utils import normalize_list_input, parse_address


class BookmarkInfo(TypedDict):
    """Information about a bookmark."""

    address: str
    title: str
    description: str


class BookmarkListResult(TypedDict):
    """Result of listing bookmarks."""

    bookmarks: list[BookmarkInfo]
    total: int
    error: NotRequired[str]


class BookmarkResult(TypedDict):
    """Result of a single bookmark operation."""

    address: str
    title: NotRequired[str]
    success: bool
    error: NotRequired[str]


class BookmarkFolderInfo(TypedDict):
    """Information about a bookmark folder."""

    name: str
    path: str


class FolderResult(TypedDict):
    """Result of folder operations."""

    name: str
    success: bool
    error: NotRequired[str]


class JumpResult(TypedDict):
    """Result of jumping to a bookmark."""

    address: str
    success: bool
    error: NotRequired[str]


def _get_bookmarks_for_widget(widget) -> list[tuple[str, str, str]]:
    """Get all bookmarks for a specific widget.

    Args:
        widget: The IDA widget (e.g., "IDA View-A", "Pseudocode-1")

    Returns:
        List of (address_hex, title, description) tuples
    """
    results = []
    try:
        userdata = ida_kernwin.get_viewer_user_data(widget)
        if userdata is None:
            return results

        for loc, desc in ida_moves.bookmarks_t(widget):
            try:
                place = loc.place()
                addr = place.toEA()
                address_hex = f"0x{addr:x}"
                title = ""
                description = str(desc) if desc else ""
                results.append((address_hex, title, description))
            except Exception:
                continue
    except Exception:
        pass
    return results


def _get_all_bookmarks() -> list[tuple[str, str, str]]:
    """Get all bookmarks across all address-based widgets.

    Returns:
        List of (address_hex, title, description) tuples
    """
    all_bookmarks = []
    seen = set()

    for widget in ida_kernwin.get_widgets(None):
        try:
            title = ida_kernwin.get_widget_title(widget)
            if not title:
                continue
            if (
                "IDA View" not in title
                and "Pseudocode" not in title
                and "Hex View" not in title
            ):
                continue

            bookmarks = _get_bookmarks_for_widget(widget)
            for addr, title, desc in bookmarks:
                if addr in seen:
                    continue
                seen.add(addr)
                all_bookmarks.append((addr, title, desc))
        except Exception:
            continue

    return all_bookmarks


@tool
@idasync
def list_bookmarks(
    filter: Annotated[str, "Optional filter for bookmark address or description"] = "",
) -> BookmarkListResult:
    """List all bookmarks in the current database.

    Provides optional filtering by address or description text.
    Use this to discover existing bookmarks before adding or removing.
    """
    try:
        all_bookmarks = _get_all_bookmarks()

        filtered = []
        filter_lower = filter.strip().lower() if filter else ""

        for addr, title, desc in all_bookmarks:
            if filter_lower:
                if (
                    filter_lower not in addr.lower()
                    and filter_lower not in title.lower()
                    and filter_lower not in desc.lower()
                ):
                    continue
            filtered.append(
                {
                    "address": addr,
                    "title": title,
                    "description": desc,
                }
            )

        return {
            "bookmarks": filtered,
            "total": len(filtered),
        }
    except Exception as e:
        return {
            "bookmarks": [],
            "total": 0,
            "error": str(e),
        }


@tool
@idasync
def add_bookmark(
    address: Annotated[str, "Address to bookmark (e.g., '0x401000' or 'main')"],
    description: Annotated[str, "Bookmark description text"],
    title: Annotated[str, "Optional short title (default: empty)"] = "",
) -> BookmarkResult:
    """Add a bookmark at the specified address.

    Creates a new bookmark at the given address with the provided description.
    The bookmark will appear in IDA's bookmark list (Ctrl+M) and navigation.
    """
    try:
        ea = parse_address(address)
    except Exception as e:
        return {
            "address": address,
            "success": False,
            "error": f"Invalid address: {e}",
        }

    try:
        widget = ida_kernwin.get_current_widget()
        if not widget:
            return {
                "address": address,
                "success": False,
                "error": "No active widget",
            }

        userdata = ida_kernwin.get_viewer_user_data(widget)
        if userdata is None:
            return {
                "address": address,
                "success": False,
                "error": "Cannot get viewer user data",
            }

        entry = ida_moves.lochist_entry_t()
        entry.place(ida_kernwin.place_t(ea))

        desc = description if description else ""
        result = ida_moves.bookmarks_t.mark(entry, 0, title, desc, userdata)

        if result == 0:
            return {
                "address": address,
                "title": title,
                "success": True,
            }
        else:
            return {
                "address": address,
                "success": False,
                "error": f"Failed to mark bookmark (code: {result})",
            }

    except Exception as e:
        return {
            "address": address,
            "success": False,
            "error": str(e),
        }


@tool
@idasync
def remove_bookmark(
    addresses: Annotated[
        list[str] | str, "Addresses to unbookmark (e.g., '0x401000' or list)"
    ],
) -> list[BookmarkResult]:
    """Remove bookmarks at the specified addresses.

    Removes one or more bookmarks by their addresses.
    Accepts a single address or comma-separated list.
    """
    addrs = normalize_list_input(addresses)
    results = []

    for addr_str in addrs:
        try:
            ea = parse_address(addr_str)
        except Exception as e:
            results.append(
                {
                    "address": addr_str,
                    "success": False,
                    "error": f"Invalid address: {e}",
                }
            )
            continue

        try:
            widget = ida_kernwin.get_current_widget()
            if not widget:
                results.append(
                    {
                        "address": addr_str,
                        "success": False,
                        "error": "No active widget",
                    }
                )
                continue

            userdata = ida_kernwin.get_viewer_user_data(widget)
            if userdata is None:
                results.append(
                    {
                        "address": addr_str,
                        "success": False,
                        "error": "Cannot get viewer user data",
                    }
                )
                continue

            entry = ida_moves.lochist_entry_t()
            entry.place(ida_kernwin.place_t(ea))

            index = ida_moves.bookmarks_t.find_index(entry, userdata)
            if index == idaapi.BADADDR:
                results.append(
                    {
                        "address": addr_str,
                        "success": False,
                        "error": "Bookmark not found",
                    }
                )
                continue

            success = ida_moves.bookmarks_t.erase(entry, index, userdata)
            results.append(
                {
                    "address": addr_str,
                    "success": success,
                }
            )

        except Exception as e:
            results.append(
                {
                    "address": addr_str,
                    "success": False,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def jump_to_bookmark(
    address: Annotated[str, "Bookmark address to jump to"],
) -> JumpResult:
    """Jump to a bookmarked address.

    Navigates IDA view to the specified bookmarked address.
    Equivalent to pressing Ctrl+M and selecting a bookmark.
    """
    try:
        ea = parse_address(address)
    except Exception as e:
        return {
            "address": address,
            "success": False,
            "error": f"Invalid address: {e}",
        }

    try:
        success = ida_kernwin.jump_to(ea)
        return {
            "address": address,
            "success": success,
        }
    except Exception as e:
        return {
            "address": address,
            "success": False,
            "error": str(e),
        }


# Bookmark folder operations - IDA 7.6+
# Note: Folders use dirtree; implementing if there's demand


@tool
@idasync
def create_bookmark_folder(
    name: Annotated[str, "New folder name"],
) -> FolderResult:
    """Create a new bookmark folder (IDA 7.6+).

    Creates a folder for organizing bookmarks.
    Note: This feature requires IDA 7.6 or later.
    """
    return {
        "name": name,
        "success": False,
        "error": "Bookmark folders not yet implemented",
    }


@tool
@idasync
def delete_bookmark_folder(
    name: Annotated[str, "Folder name to delete"],
) -> FolderResult:
    """Delete a bookmark folder (IDA 7.6+).

    Removes an existing bookmark folder.
    Note: This feature requires IDA 7.6 or later.
    """
    return {
        "name": name,
        "success": False,
        "error": "Bookmark folders not yet implemented",
    }
