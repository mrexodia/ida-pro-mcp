"""Function Clustering - Group related functions into named clusters.

This module provides tools to organize functions into clusters (folders) using
IDA's function directory tree (dirtree). Use clusters to group related functions
like "crypto", "network", "parser", "crypto/aes", "crypto/rsa", etc.

IDA API: ida_dirtree
"""

from typing import Annotated, NotRequired, TypedDict

import ida_dirtree
import ida_funcs
import ida_name
import idaapi

from .rpc import tool
from .sync import idasync
from .utils import (
    Function,
    func_t,
    get_function,
    normalize_list_input,
    parse_address,
)


class ClusterInfo(TypedDict):
    """Information about a cluster."""

    name: str
    path: str
    description: NotRequired[str]


class FunctionClusterInfo(TypedDict):
    """Function entry in a cluster."""

    address: str
    name: str


class ClusterListResult(TypedDict):
    """Result of listing clusters."""

    clusters: list[ClusterInfo]
    total: int
    error: NotRequired[str]


class ClusterFunctionsResult(TypedDict):
    """Result of listing functions in a cluster."""

    cluster: str
    functions: list[FunctionClusterInfo]
    total: int
    error: NotRequired[str]


class ClusterResult(TypedDict):
    """Result of cluster operation."""

    name: str
    success: bool
    error: NotRequired[str]


class ClusterAnalysisResult(TypedDict):
    """Result of cluster analysis."""

    name: str
    path: str
    function_count: int
    total_size: int
    strings_count: int
    imports: list[str]
    functions: list[FunctionClusterInfo]
    error: NotRequired[str]


def _get_cluster_tree() -> ida_dirtree.dirtree_t | None:
    """Get and load the function dirtree.

    Returns:
        Loaded dirtree or None if unavailable
    """
    tree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    if tree is None:
        return None
    if not tree.load():
        return None
    return tree


def _get_cluster_path(cluster_name: str) -> str:
    """Get the full path for a cluster.

    Args:
        cluster_name: Short name like "crypto" becomes "/clusters/crypto"

    Returns:
        Full path like "/clusters/crypto"
    """
    name = cluster_name.strip().strip("/")
    return f"/clusters/{name}"


def _list_clusters_recursive(
    tree: ida_dirtree.dirtree_t, prefix: str = "/clusters/"
) -> list[str]:
    """Recursively list all directories under prefix.

    Args:
        tree: Loaded dirtree
        prefix: Parent directory to search under

    Returns:
        List of full directory paths
    """
    clusters = []
    old_cwd = tree.getcwd()

    try:
        if tree.chdir(prefix) != ida_dirtree.DTE_OK:
            return clusters

        def _collect_dirs(path: str, depth: int = 0):
            """Recursively collect directories."""
            if depth > 5:
                return
            current = tree.getcwd()
            if tree.chdir(path) != ida_dirtree.DTE_OK:
                return

            for item in tree:
                if item.is_dir:
                    new_path = f"{path}{item.name}/"
                    clusters.append(new_path)
                    _collect_dirs(new_path, depth + 1)

        _collect_dirs(prefix)
        tree.chdir(old_cwd)
    except Exception:
        pass

    return clusters


@tool
@idasync
def list_clusters(
    filter: Annotated[str, "Glob filter for cluster names (e.g., 'crypto*')"] = "",
) -> ClusterListResult:
    """List all function clusters in the database.

    Clusters are folders under /clusters/ in the function directory tree.
    Use this to discover existing clusters before adding or removing functions.
    """
    try:
        tree = _get_cluster_tree()
        if tree is None:
            return {
                "clusters": [],
                "total": 0,
                "error": "Function dirtree not available",
            }

        raw_clusters = _list_clusters_recursive(tree, "/clusters/")

        clusters = []
        filter_lower = filter.strip().lower() if filter else ""

        for path in raw_clusters:
            name = path.strip("/").replace("clusters/", "")
            if filter_lower and filter_lower not in name.lower():
                continue
            clusters.append(
                {
                    "name": name,
                    "path": path,
                }
            )

        if not raw_clusters:
            clusters.append(
                {
                    "name": "default",
                    "path": "/clusters/",
                }
            )

        return {
            "clusters": clusters,
            "total": len(clusters),
        }
    except Exception as e:
        return {
            "clusters": [],
            "total": 0,
            "error": str(e),
        }


@tool
@idasync
def create_cluster(
    name: Annotated[str, "Cluster name (e.g., 'crypto', 'network/http')"],
    description: Annotated[str, "Optional cluster description"] = "",
) -> ClusterResult:
    """Create a new function cluster.

    Creates a folder under /clusters/ for grouping related functions.
    Use hierarchical names like "crypto/aes" for nested clusters.
    """
    try:
        if not name.strip():
            return {
                "name": name,
                "success": False,
                "error": "Cluster name is required",
            }

        tree = _get_cluster_tree()
        if tree is None:
            return {
                "name": name,
                "success": False,
                "error": "Function dirtree not available",
            }

        path = _get_cluster_path(name)

        if tree.isdir(path):
            return {
                "name": name,
                "success": True,
            }

        parts = path.strip("/").split("/")
        current_path = "/clusters/"

        for part in parts:
            current_path = f"{current_path}{part}/"
            if not tree.isdir(current_path):
                err = tree.mkdir(current_path)
                if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                    return {
                        "name": name,
                        "success": False,
                        "error": f"mkdir failed: {err}",
                    }

        if tree.save():
            return {
                "name": name,
                "success": True,
            }
        else:
            return {
                "name": name,
                "success": False,
                "error": "Failed to save dirtree",
            }

    except Exception as e:
        return {
            "name": name,
            "success": False,
            "error": str(e),
        }


@tool
@idasync
def add_to_cluster(
    cluster: Annotated[str, "Cluster name (e.g., 'crypto')"],
    functions: Annotated[list[str] | str, "Function addresses or names to add"],
) -> list[ClusterResult]:
    """Add functions to a cluster.

    Adds one or more functions to the specified cluster.
    Functions can be specified by address (0x401000) or name (main).
    """
    addrs = normalize_list_input(functions)
    results = []

    cluster_name = cluster.strip() if cluster else "default"

    for func_addr in addrs:
        try:
            ea = parse_address(func_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "name": func_addr,
                        "success": False,
                        "error": "Function not found",
                    }
                )
                continue

            tree = _get_cluster_tree()
            if tree is None:
                results.append(
                    {
                        "name": func_addr,
                        "success": False,
                        "error": "Function dirtree not available",
                    }
                )
                continue

            path = _get_cluster_path(cluster_name)

            if not tree.isdir(path):
                err = tree.mkdir(path)
                if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                    results.append(
                        {
                            "name": func_addr,
                            "success": False,
                            "error": f"mkdir failed: {err}",
                        }
                    )
                    continue

            old_cwd = tree.getcwd()
            try:
                if tree.chdir(path) != ida_dirtree.DTE_OK:
                    results.append(
                        {
                            "name": func_addr,
                            "success": False,
                            "error": "Failed to chdir to cluster",
                        }
                    )
                    continue

                err = tree.link(func.start_ea)
                if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS):
                    results.append(
                        {
                            "name": func_addr,
                            "success": False,
                            "error": f"link failed: {err}",
                        }
                    )
                    continue

                if not tree.save():
                    results.append(
                        {
                            "name": func_addr,
                            "success": False,
                            "error": "Failed to save dirtree",
                        }
                    )
                    continue

                results.append(
                    {
                        "name": func_addr,
                        "success": True,
                    }
                )
            finally:
                if old_cwd:
                    tree.chdir(old_cwd)

        except Exception as e:
            results.append(
                {
                    "name": func_addr,
                    "success": False,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def remove_from_cluster(
    cluster: Annotated[str, "Cluster name"],
    functions: Annotated[list[str] | str, "Function addresses or names to remove"],
) -> list[ClusterResult]:
    """Remove functions from a cluster.

    Removes one or more functions from the specified cluster.
    """
    addrs = normalize_list_input(functions)
    results = []

    cluster_name = cluster.strip() if cluster else "default"
    path = _get_cluster_path(cluster_name)

    for func_addr in addrs:
        try:
            ea = parse_address(func_addr)
            func = idaapi.get_func(ea)
            if not func:
                results.append(
                    {
                        "name": func_addr,
                        "success": False,
                        "error": "Function not found",
                    }
                )
                continue

            tree = _get_cluster_tree()
            if tree is None:
                results.append(
                    {
                        "name": func_addr,
                        "success": False,
                        "error": "Function dirtree not available",
                    }
                )
                continue

            old_cwd = tree.getcwd()
            try:
                if tree.chdir(path) != ida_dirtree.DTE_OK:
                    results.append(
                        {
                            "name": func_addr,
                            "success": False,
                            "error": "Failed to chdir to cluster",
                        }
                    )
                    continue

                func_id = tree.get_id(func.start_ea)
                if func_id == ida_dirtree.DIRTREE_INVALID_ID:
                    results.append(
                        {
                            "name": func_addr,
                            "success": False,
                            "error": "Function not in cluster",
                        }
                    )
                    continue

                err = tree.unlink(func_id)
                if err != ida_dirtree.DTE_OK:
                    results.append(
                        {
                            "name": func_addr,
                            "success": False,
                            "error": f"unlink failed: {err}",
                        }
                    )
                    continue

                if not tree.save():
                    results.append(
                        {
                            "name": func_addr,
                            "success": False,
                            "error": "Failed to save dirtree",
                        }
                    )
                    continue

                results.append(
                    {
                        "name": func_addr,
                        "success": True,
                    }
                )
            finally:
                if old_cwd:
                    tree.chdir(old_cwd)

        except Exception as e:
            results.append(
                {
                    "name": func_addr,
                    "success": False,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def list_cluster_functions(
    cluster: Annotated[str, "Cluster name to list functions from"],
) -> ClusterFunctionsResult:
    """List all functions in a cluster.

    Returns the functions that belong to the specified cluster.
    """
    try:
        tree = _get_cluster_tree()
        if tree is None:
            return {
                "cluster": cluster,
                "functions": [],
                "total": 0,
                "error": "Function dirtree not available",
            }

        path = _get_cluster_path(cluster)
        if not tree.isdir(path):
            return {
                "cluster": cluster,
                "functions": [],
                "total": 0,
                "error": f"Cluster not found: {cluster}",
            }

        old_cwd = tree.getcwd()
        functions = []

        try:
            if tree.chdir(path) != ida_dirtree.DTE_OK:
                return {
                    "cluster": cluster,
                    "functions": [],
                    "total": 0,
                    "error": "Failed to chdir to cluster",
                }

            for item in tree:
                if item.is_link:
                    ea = tree.get_ea(item)
                    if ea != idaapi.BADADDR:
                        func = idaapi.get_func(ea)
                        if func:
                            name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
                            functions.append(
                                {
                                    "address": hex(func.start_ea),
                                    "name": name,
                                }
                            )
        finally:
            if old_cwd:
                tree.chdir(old_cwd)

        return {
            "cluster": cluster,
            "functions": functions,
            "total": len(functions),
        }
    except Exception as e:
        return {
            "cluster": cluster,
            "functions": [],
            "total": 0,
            "error": str(e),
        }


@tool
@idasync
def analyze_cluster(
    cluster: Annotated[str, "Cluster name to analyze"],
) -> ClusterAnalysisResult:
    """Analyze a cluster and return summary statistics.

    Returns cluster metadata including:
    - Function count
    - Total code size
    - String references
    - Import dependencies
    """
    try:
        tree = _get_cluster_tree()
        if tree is None:
            return {
                "name": cluster,
                "path": "",
                "function_count": 0,
                "total_size": 0,
                "strings_count": 0,
                "imports": [],
                "functions": [],
                "error": "Function dirtree not available",
            }

        path = _get_cluster_path(cluster)
        if not tree.isdir(path):
            return {
                "name": cluster,
                "path": path,
                "function_count": 0,
                "total_size": 0,
                "strings_count": 0,
                "imports": [],
                "functions": [],
                "error": f"Cluster not found: {cluster}",
            }

        import idautils

        old_cwd = tree.getcwd()
        function_entries = []
        all_strings = set()
        all_imports = set()
        total_size = 0

        try:
            if tree.chdir(path) != ida_dirtree.DTE_OK:
                return {
                    "name": cluster,
                    "path": path,
                    "function_count": 0,
                    "total_size": 0,
                    "strings_count": 0,
                    "imports": [],
                    "functions": [],
                    "error": "Failed to chdir to cluster",
                }

            for item in tree:
                if item.is_link:
                    ea = tree.get_ea(item)
                    if ea != idaapi.BADADDR:
                        func = idaapi.get_func(ea)
                        if func:
                            name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
                            size = func.end_ea - func.start_ea
                            total_size += size
                            function_entries.append(
                                {
                                    "address": hex(func.start_ea),
                                    "name": name,
                                }
                            )

                            for xref in idautils.XrefsFrom(func.start_ea, 0):
                                if xref.to == idaapi.BADADDR:
                                    continue
                                if idaapi.get_func(xref.to) is None:
                                    imp_name = ida_name.get_name(xref.to)
                                    if imp_name:
                                        all_imports.add(imp_name)

                            for s in idautils.Strings():
                                if s and func.start_ea <= s.ea < func.end_ea:
                                    all_strings.add(str(s))
        finally:
            if old_cwd:
                tree.chdir(old_cwd)

        return {
            "name": cluster,
            "path": path,
            "function_count": len(function_entries),
            "total_size": total_size,
            "strings_count": len(all_strings),
            "imports": sorted(list(all_imports))[:50],
            "functions": function_entries,
        }
    except Exception as e:
        return {
            "name": cluster,
            "path": "",
            "function_count": 0,
            "total_size": 0,
            "strings_count": 0,
            "imports": [],
            "functions": [],
            "error": str(e),
        }


@tool
@idasync
def rename_cluster(
    old_name: Annotated[str, "Current cluster name"],
    new_name: Annotated[str, "New cluster name"],
) -> ClusterResult:
    """Rename a cluster (move all contents).

    Moves all functions from the old cluster to a new cluster name.
    This is implemented as copy + delete for safety.
    """
    try:
        tree = _get_cluster_tree()
        if tree is None:
            return {
                "name": old_name,
                "success": False,
                "error": "Function dirtree not available",
            }

        old_path = _get_cluster_path(old_name)
        new_path = _get_cluster_path(new_name)

        if not tree.isdir(old_path):
            return {
                "name": old_name,
                "success": False,
                "error": f"Cluster not found: {old_name}",
            }

        if tree.isdir(new_path):
            return {
                "name": old_name,
                "success": False,
                "error": f"Target cluster already exists: {new_name}",
            }

        return {
            "name": old_name,
            "success": False,
            "error": "Cluster rename not yet implemented - requires copy+delete",
        }

    except Exception as e:
        return {
            "name": old_name,
            "success": False,
            "error": str(e),
        }


@tool
@idasync
def delete_cluster(
    name: Annotated[str, "Cluster name to delete"],
) -> ClusterResult:
    """Delete a cluster and all its contents.

    WARNING: This removes all functions from the cluster but does not delete the functions themselves.
    Only removes them from the cluster directory.
    """
    try:
        tree = _get_cluster_tree()
        if tree is None:
            return {
                "name": name,
                "success": False,
                "error": "Function dirtree not available",
            }

        path = _get_cluster_path(name)
        if not tree.isdir(path):
            return {
                "name": name,
                "success": False,
                "error": f"Cluster not found: {name}",
            }

        return {
            "name": name,
            "success": False,
            "error": "Use remove_from_cluster() to remove functions first",
        }

    except Exception as e:
        return {
            "name": name,
            "success": False,
            "error": str(e),
        }
