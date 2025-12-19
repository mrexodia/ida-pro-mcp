# IDA Pro MCP Test Progress

## Phase 1: Framework + Basic Tests

**Status**: In Progress  
**Goal**: Establish working test infrastructure with basic smoke tests

### Tasks

| Task | Status | Notes |
|------|--------|-------|
| Create `devdocs/` directory | ✅ Complete | |
| Create `devdocs/test-plan.md` | ✅ Complete | |
| Create `devdocs/test-progress.md` | ✅ Complete | This file |
| Create `tests.py` module | ✅ Complete | Test decorator, runner, helpers |
| Move `@test` from `rpc.py` to `tests.py` | ✅ Complete | Removed from rpc.py |
| Implement `run_tests()` function | ✅ Complete | Pattern matching, verbose output |
| Implement test helper assertions | ✅ Complete | `assert_*` functions |
| Implement test helper utilities | ✅ Complete | `get_any_*` functions |
| Add `main()` for standalone runner | ✅ Complete | idalib-based entry point |
| Add `ida-mcp-test` to pyproject.toml | ✅ Complete | Script entry point |
| Update `__init__.py` exports | ✅ Complete | Export `run_tests`, `test` |
| Update `api_core.py` test import | ✅ Complete | Changed to `from .tests` |
| Rewrite `test_idb_meta` | ✅ Complete | Uses new helpers |
| Add basic `api_core.py` tests | ✅ Complete | 8 tests total |
| Test framework in IDA console | ⬜ Pending | Verify `run_tests()` works |
| Test standalone runner | ⬜ Pending | Verify `ida-mcp-test` works |

### Phase 1 Test List (api_core)

| Test | Status | Description |
|------|--------|-------------|
| `test_idb_meta` | ✅ | Metadata has required keys and valid values |
| `test_list_funcs` | ✅ | Returns functions with proper structure |
| `test_list_funcs_pagination` | ✅ | Offset/count parameters work |
| `test_lookup_funcs_by_address` | ✅ | Can look up function by address |
| `test_lookup_funcs_invalid` | ✅ | Invalid address raises IDAError |
| `test_strings` | ✅ | Returns strings with proper structure |
| `test_int_convert` | ✅ | Number conversion works |
| `test_segments` | ✅ | Returns segments list |

### Deliverables

1. ✅ `devdocs/test-plan.md` - Test plan document
2. ✅ `devdocs/test-progress.md` - Progress tracking (this file)
3. ✅ `src/ida_pro_mcp/ida_mcp/tests.py` - Complete test framework
4. ✅ Updated `pyproject.toml` with `ida-mcp-test` entry point
5. ✅ Updated `api_core.py` with 8 working tests
6. ✅ Updated `__init__.py` with exports

### Exit Criteria

- [ ] `from ida_mcp.tests import run_tests; run_tests()` works in IDA console
- [ ] `ida-mcp-test crackme03.elf` works from command line
- [ ] All Phase 1 tests pass on `crackme03.elf`
- [ ] Verbose output shows pass/fail with tracebacks for failures

---

## Phase 2: Category Implementation (Parallel)

**Status**: Blocked on Phase 1  
**Goal**: Comprehensive test coverage across all safe API modules

Each category can be implemented in parallel by different agents.

### Category: api_analysis

**Estimated tests**: 12-15

| Test | Status | Description |
|------|--------|-------------|
| `test_decompile_valid_function` | ⬜ | Decompile returns code for valid function |
| `test_decompile_invalid_address` | ⬜ | Raises IDAError for invalid address |
| `test_decompile_batch` | ⬜ | Handles multiple addresses |
| `test_disasm_valid_function` | ⬜ | Disassembly returns lines |
| `test_disasm_pagination` | ⬜ | Offset/max_instructions work |
| `test_xrefs_to` | ⬜ | Returns cross-references |
| `test_xrefs_to_invalid` | ⬜ | Handles invalid address |
| `test_callees` | ⬜ | Returns called functions |
| `test_callers` | ⬜ | Returns calling functions |
| `test_entrypoints` | ⬜ | Returns entry points |
| `test_analyze_funcs` | ⬜ | Comprehensive analysis returns all fields |
| `test_find_bytes` | ⬜ | Byte pattern search works |
| `test_find_insns` | ⬜ | Instruction sequence search works |
| `test_basic_blocks` | ⬜ | Returns CFG blocks |
| `test_callgraph` | ⬜ | Call graph traversal works |

### Category: api_memory

**Estimated tests**: 6-8

| Test | Status | Description |
|------|--------|-------------|
| `test_get_bytes` | ⬜ | Read raw bytes from valid address |
| `test_get_bytes_invalid` | ⬜ | Handles invalid address |
| `test_get_u8` | ⬜ | Read u8 value |
| `test_get_u16` | ⬜ | Read u16 value |
| `test_get_u32` | ⬜ | Read u32 value |
| `test_get_u64` | ⬜ | Read u64 value |
| `test_get_string` | ⬜ | Read string at valid address |
| `test_get_global_value` | ⬜ | Read global by name/address |

### Category: api_types

**Estimated tests**: 6-8

| Test | Status | Description |
|------|--------|-------------|
| `test_structs_list` | ⬜ | List returns structures |
| `test_struct_info` | ⬜ | Get struct details |
| `test_struct_info_not_found` | ⬜ | Handles nonexistent struct |
| `test_search_structs` | ⬜ | Filter by name works |
| `test_infer_types` | ⬜ | Type inference returns result |
| `test_declare_type` | ⬜ | Declare C type (with cleanup) |

### Category: api_modify

**Estimated tests**: 4-6

| Test | Status | Description |
|------|--------|-------------|
| `test_set_comment_roundtrip` | ⬜ | Set/clear comment |
| `test_rename_function_roundtrip` | ⬜ | Rename/restore function |
| `test_rename_global_roundtrip` | ⬜ | Rename/restore global |
| `test_rename_local_roundtrip` | ⬜ | Rename/restore local var |
| `test_patch_asm` | ⬜ | Assembly patching (with cleanup) |

### Category: api_stack

**Estimated tests**: 3-4

| Test | Status | Description |
|------|--------|-------------|
| `test_stack_frame` | ⬜ | Get stack variables |
| `test_stack_frame_no_function` | ⬜ | Handles invalid address |
| `test_declare_delete_stack` | ⬜ | Create/delete stack var |

### Category: api_resources

**Estimated tests**: 8-10

| Test | Status | Description |
|------|--------|-------------|
| `test_resource_idb_metadata` | ⬜ | ida://idb/metadata works |
| `test_resource_idb_segments` | ⬜ | ida://idb/segments works |
| `test_resource_functions` | ⬜ | ida://functions works |
| `test_resource_function_addr` | ⬜ | ida://function/{addr} works |
| `test_resource_globals` | ⬜ | ida://globals works |
| `test_resource_strings` | ⬜ | ida://strings works |
| `test_resource_imports` | ⬜ | ida://imports works |
| `test_resource_structs` | ⬜ | ida://structs works |
| `test_resource_xrefs_to` | ⬜ | ida://xrefs/to/{addr} works |
| `test_resource_xrefs_from` | ⬜ | ida://xrefs/from/{addr} works |

---

## Summary

| Phase | Category | Tests | Status |
|-------|----------|-------|--------|
| 1 | framework | - | ✅ Complete |
| 1 | api_core | 8 | ✅ Complete |
| 2 | api_analysis | 15 | ⬜ Blocked |
| 2 | api_memory | 8 | ⬜ Blocked |
| 2 | api_types | 6 | ⬜ Blocked |
| 2 | api_modify | 5 | ⬜ Blocked |
| 2 | api_stack | 3 | ⬜ Blocked |
| 2 | api_resources | 10 | ⬜ Blocked |
| **Total** | | **~55** | |

---

## Legend

- ⬜ Pending / Not Started
- 🔄 In Progress  
- ✅ Complete
- ⏭️ Skipped
- ❌ Blocked / Failed
