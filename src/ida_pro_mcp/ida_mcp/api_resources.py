"""MCP Resources - browsable IDB state

Resources represent browsable state (read-only data) following MCP's philosophy.
Use tools for actions that modify state or perform expensive computations.
"""

from typing import Annotated

import ida_funcs
import ida_nalt
import ida_segment
import ida_typeinf
import idaapi
import idautils
import idc

from .rpc import resource
from .sync import idasync
from .utils import (
   Metadata,
   Segment,
   StructureDefinition,
   StructureMember,
   get_image_size,
   parse_address,
)


# ============================================================================
# Core IDB State
# ============================================================================


@resource("ida://idb/metadata")
@idasync
def idb_metadata_resource() -> Metadata:
   """Get IDB file metadata (path, arch, base address, size, hashes)"""
   import hashlib

   path = idc.get_idb_path()
   module = ida_nalt.get_root_filename()
   base = hex(idaapi.get_imagebase())
   size = hex(get_image_size())

   input_path = ida_nalt.get_input_file_path()
   try:
      with open(input_path, "rb") as f:
         data = f.read()
      md5 = hashlib.md5(data).hexdigest()
      sha256 = hashlib.sha256(data).hexdigest()
      import zlib

      crc32 = hex(zlib.crc32(data) & 0xFFFFFFFF)
      filesize = hex(len(data))
   except Exception:
      md5 = sha256 = crc32 = filesize = "unavailable"

   return Metadata(
      path=path,
      module=module,
      base=base,
      size=size,
      md5=md5,
      sha256=sha256,
      crc32=crc32,
      filesize=filesize,
   )


@resource("ida://idb/segments")
@idasync
def idb_segments_resource() -> list[Segment]:
   """Get all memory segments with permissions"""
   segments = []
   for seg_ea in idautils.Segments():
      seg = idaapi.getseg(seg_ea)
      if seg:
         perms = []
         if seg.perm & idaapi.SEGPERM_READ:
            perms.append("r")
         if seg.perm & idaapi.SEGPERM_WRITE:
            perms.append("w")
         if seg.perm & idaapi.SEGPERM_EXEC:
            perms.append("x")

         segments.append(
            Segment(
               name=ida_segment.get_segm_name(seg),
               start=hex(seg.start_ea),
               end=hex(seg.end_ea),
               size=hex(seg.size()),
               permissions="".join(perms) if perms else "---",
            )
         )
   return segments


@resource("ida://idb/entrypoints")
@idasync
def idb_entrypoints_resource() -> list[dict]:
   """Get entry points (main, TLS callbacks, etc.)"""
   entrypoints = []
   entry_count = ida_nalt.get_entry_qty()
   for i in range(entry_count):
      ordinal = ida_nalt.get_entry_ordinal(i)
      ea = ida_nalt.get_entry(ordinal)
      name = ida_nalt.get_entry_name(ordinal)
      entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
   return entrypoints


# ============================================================================
# UI State
# ============================================================================


@resource("ida://cursor")
@idasync
def cursor_resource() -> dict:
   """Get current cursor position and function"""
   import ida_kernwin

   ea = ida_kernwin.get_screen_ea()
   func = idaapi.get_func(ea)

   result = {"addr": hex(ea)}
   if func:
      try:
         func_name = func.get_name()
      except AttributeError:
         func_name = ida_funcs.get_func_name(func.start_ea)

      result["function"] = {
         "addr": hex(func.start_ea),
         "name": func_name,
      }

   return result


@resource("ida://selection")
@idasync
def selection_resource() -> dict:
   """Get current selection range (if any)"""
   import ida_kernwin

   start = ida_kernwin.read_range_selection(None)
   if start:
      return {"start": hex(start[0]), "end": hex(start[1]) if start[1] else None}
   return {"selection": None}


# ============================================================================
# Type Information
# ============================================================================


@resource("ida://types")
@idasync
def types_resource() -> list[dict]:
   """Get all local types"""
   types = []
   for ordinal in range(1, ida_typeinf.get_ordinal_qty(None)):
      tif = ida_typeinf.tinfo_t()
      if tif.get_numbered_type(None, ordinal):
         name = tif.get_type_name()
         types.append({"ordinal": ordinal, "name": name, "type": str(tif)})
   return types


@resource("ida://structs")
@idasync
def structs_resource() -> list[dict]:
   """Get all structures/unions"""
   structs = []
   limit = ida_typeinf.get_ordinal_limit()
   for ordinal in range(1, limit):
      tif = ida_typeinf.tinfo_t()
      if tif.get_numbered_type(None, ordinal) and tif.is_udt():
         udt_data = ida_typeinf.udt_type_data_t()
         is_union = False
         if tif.get_udt_details(udt_data):
            is_union = udt_data.is_union
         structs.append(
            {
               "name": tif.get_type_name(),
               "size": hex(tif.get_size()),
               "is_union": is_union,
            }
         )
   return structs


@resource("ida://struct/{name}")
@idasync
def struct_name_resource(name: Annotated[str, "Structure name"]) -> dict:
   """Get structure definition with fields"""
   tif = ida_typeinf.tinfo_t()
   if not tif.get_named_type(None, name):
      return {"error": f"Structure not found: {name}"}

   if not tif.is_udt():
      return {"error": f"'{name}' is not a structure/union"}

   udt_data = ida_typeinf.udt_type_data_t()
   if not tif.get_udt_details(udt_data):
      return {"error": f"Failed to get struct details for '{name}'"}

   members = []
   for member in udt_data:
      members.append(
         StructureMember(
            name=member.name,
            offset=hex(member.offset // 8),
            size=hex(member.size // 8),
            type=str(member.type),
         )
      )

   return StructureDefinition(
      name=name, size=hex(tif.get_size()), members=members
   )


# ============================================================================
# Import/Export Lookup by Name
# ============================================================================


@resource("ida://import/{name}")
@idasync
def import_name_resource(name: Annotated[str, "Import name"]) -> dict:
   """Get specific import details by name"""
   nimps = ida_nalt.get_import_module_qty()
   for i in range(nimps):
      module = ida_nalt.get_import_module_name(i)
      result = {}

      def callback(ea, imp_name, ordinal):
         if imp_name == name or f"ord_{ordinal}" == name:
            result.update(
               {
                  "addr": hex(ea),
                  "name": imp_name or f"ord_{ordinal}",
                  "module": module,
                  "ordinal": ordinal,
               }
            )
            return False  # Stop enumeration
         return True

      ida_nalt.enum_import_names(i, callback)
      if result:
         return result

   return {"error": f"Import not found: {name}"}


@resource("ida://export/{name}")
@idasync
def export_name_resource(name: Annotated[str, "Export name"]) -> dict:
   """Get specific export details by name"""
   entry_count = ida_nalt.get_entry_qty()
   for i in range(entry_count):
      ordinal = ida_nalt.get_entry_ordinal(i)
      ea = ida_nalt.get_entry(ordinal)
      entry_name = ida_nalt.get_entry_name(ordinal)

      if entry_name == name:
         return {
            "addr": hex(ea),
            "name": entry_name,
            "ordinal": ordinal,
         }

   return {"error": f"Export not found: {name}"}


# ============================================================================
# Cross-references
# ============================================================================


@resource("ida://xrefs/from/{addr}")
@idasync
def xrefs_from_resource(addr: Annotated[str, "Source address"]) -> list[dict]:
   """Get cross-references from address"""
   ea = parse_address(addr)
   xrefs = []
   for xref in idautils.XrefsFrom(ea, 0):
      xrefs.append(
         {
            "addr": hex(xref.to),
            "type": "code" if xref.iscode else "data",
         }
      )
   return xrefs
