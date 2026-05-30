"""
Vendored sigmaker core — signature creation and scanning engine.

Original: sigmaker.py - IDA Python Signature Maker
https://github.com/mahmoudimus/ida-sigmaker
by @mahmoudimus (Mahmoud Abdelkader)

This is a stripped-down, self-contained copy of the sigmaker library
with GUI/plugin code removed.  Only the engine classes are kept so that
api_sigmaker.py can use them without an external dependency.

Synced with upstream v1.8.0.  Ported engine improvements over the original
v1.6.0 vendoring:
  - WildcardPolicy.for_x86 no longer wildcards immediates (literals baked
    into the encoding do not move between builds, so wildcarding them only
    removes bytes that would have made the signature unique).
  - SignatureSearcher.is_unique bails at the second match instead of
    enumerating every match -- a large win on big binaries where a short,
    common prefix can match millions of positions.
  - GeneratedSignature orders by (length, wildcard_count) so the xref
    ranking prefers the most specific signature among equal-length ones.
  - MinimalFunctionSignatureGenerator finds the shortest unique signature
    anywhere inside a function body (not just from its entry point).
  - SIMD seed-and-refine helpers are carried over for parity; they are
    inert unless a compiled `_speedups` module is present.

This file has no third-party dependencies: it relies only on idaapi/idc and
the standard library. The compiled `_speedups` module is optional; when it is
absent, scanning falls back to idaapi.bin_search.

The interactive layers (IDA Forms, the plugin class, wait-box progress
dialogs, clipboard, and the cProfile diagnostics) are intentionally NOT
vendored: this engine runs inside an MCP server, where popping modal UI
or blocking on user input is never appropriate.

MIT License

Copyright (c) 2024 Mahmoud Abdelkader (@mahmoudimus)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import annotations

import array
import contextlib
import contextvars
import dataclasses
import enum
import functools
import logging
import pathlib
import re
import string
import typing

import idaapi
import idc

__author__ = "mahmoudimus"
__version__ = "1.8.0"


WILDCARD_POLICY_CTX: contextvars.ContextVar["WildcardPolicy"] = contextvars.ContextVar(
    "wildcard_policy"
)


SIMD_SPEEDUP_AVAILABLE = False
with contextlib.suppress(ImportError):
    try:
        from sigmaker._speedups import simd_scan
    except ImportError:
        from _sigmaker._speedups import simd_scan  # type: ignore[import-not-found]

    _SimdSignature = simd_scan.Signature
    _simd_scan_bytes = simd_scan.scan_bytes

    SIMD_SPEEDUP_AVAILABLE = True


# How many matches a scan loop processes between cancellation polls.
# idaapi.user_cancelled() is not a cheap predicate (it pumps the UI event
# loop), and a short, common pattern can match tens of millions of positions,
# so polling too often makes the poll itself the dominant cost. Polling every
# 65536 matches keeps that overhead near a second while leaving cancel
# responsive. Only the SIMD scan loops consult this.
_CANCEL_POLL_STRIDE: int = 65536


def _user_canceled() -> bool:
    """Headless-safe wrapper around IDA's cancellation predicate.

    IDA exposes the British spelling ``user_cancelled``. In a headless idalib
    context the function still exists and simply returns False, so polling it
    is harmless; guard anyway so the engine never hard-depends on it.
    """
    fn = getattr(idaapi, "user_cancelled", None)
    if fn is None:
        return False
    try:
        return bool(fn())
    except Exception:
        return False


def configure_logging(
    logger=None,
    logging_name="sigmaker",
    level=logging.INFO,
    handler_filters=None,
    fmt_str="[%(levelname)s] @ %(message)s",
):
    if logger is None:
        logger = logging.getLogger(logging_name)

    logger.propagate = False
    logger.setLevel(level)
    formatter = logging.Formatter(fmt_str)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(level)

    if handler_filters is not None:
        for _filter in handler_filters:
            handler.addFilter(_filter)

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    if not logger.handlers:
        logger.addHandler(handler)
    return logger


LOGGER = configure_logging()


class Unexpected(Exception):
    """Exception type used throughout the module to indicate unexpected errors."""


class UserCanceledError(Exception):
    """Raised when an optional progress reporter signals cancellation.

    Headless callers do not pass a reporter, so this is effectively inert in
    the MCP server; it is kept so the generator signatures stay compatible
    with the upstream engine.
    """


class ProgressReporter(typing.Protocol):
    """Minimal protocol for cooperative cancellation of long operations."""

    def should_cancel(self) -> bool: ...


@functools.total_ordering
@dataclasses.dataclass(frozen=True)
class IDAVersionInfo:
    major: int
    minor: int
    sdk_version: int

    def __eq__(self, other):
        if isinstance(other, IDAVersionInfo):
            return (self.major, self.minor) == (other.major, other.minor)
        if isinstance(other, tuple):
            return (self.major, self.minor) == tuple(other[:2])
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, IDAVersionInfo):
            return (self.major, self.minor) < (other.major, other.minor)
        if isinstance(other, tuple):
            return (self.major, self.minor) < tuple(other[:2])
        return NotImplemented

    @staticmethod
    @functools.cache
    def ida_version():
        version_str: str = idaapi.get_kernel_version()
        sdk_version: int = idaapi.IDA_SDK_VERSION
        major, minor = map(int, version_str.split("."))
        return IDAVersionInfo(major, minor, sdk_version)


ida_version = IDAVersionInfo.ida_version


def is_address_marked_as_code(ea: int) -> bool:
    return idaapi.is_code(idaapi.get_flags(ea))


@dataclasses.dataclass(slots=True)
class InMemoryBuffer:
    class LoadMode(enum.Enum):
        SEGMENTS = "segments"
        FILE = "file"

    file_path: pathlib.Path
    mode: LoadMode = dataclasses.field(default=LoadMode.SEGMENTS)
    _buffer: bytearray = dataclasses.field(
        default_factory=bytearray, init=False, repr=False
    )

    @property
    def file_size(self) -> int:
        return idaapi.retrieve_input_file_size()

    @property
    def imagebase(self) -> int:
        return idaapi.get_imagebase()

    def _load_segments(self):
        buf = self._buffer
        seg = idaapi.get_first_seg()
        while seg:
            size = seg.end_ea - seg.start_ea
            data = idaapi.get_bytes(seg.start_ea, size)
            if data:
                buf.extend(data)
            seg = idaapi.get_next_seg(seg.start_ea)

    def _load_input_file(self):
        if not self.file_path.exists():
            raise RuntimeError(f"Input file {self.file_path} does not exist.")
        with self.file_path.open("rb") as f:
            self._buffer = bytearray(f.read())

    @classmethod
    def load(
        cls,
        file_path: str | pathlib.Path | None = None,
        mode: "InMemoryBuffer.LoadMode" = LoadMode.SEGMENTS,
    ) -> "InMemoryBuffer":
        if file_path is None:
            file_path = idaapi.get_input_file_path()
        if isinstance(file_path, str):
            file_path = pathlib.Path(file_path)
        instance = cls(file_path=file_path, mode=mode)
        if mode == cls.LoadMode.FILE:
            instance._load_input_file()
        else:
            instance._load_segments()
        return instance

    def data(self) -> memoryview:
        return memoryview(self._buffer)

    def clear(self):
        self._buffer.clear()

    def file_offset_to_ida_addr(self, file_offset: int) -> int:
        if self.mode != self.LoadMode.FILE:
            raise RuntimeError("file_offset_to_ida_addr is only valid in 'file' mode.")
        return self.imagebase + file_offset

    def ida_addr_to_file_offset(self, ida_addr: int) -> int:
        if self.mode != self.LoadMode.FILE:
            raise RuntimeError("ida_addr_to_file_offset is only valid in 'file' mode.")
        return ida_addr - self.imagebase

    def segment_offset_to_ida_addr(self, seg_offset: int) -> int:
        if self.mode != self.LoadMode.SEGMENTS:
            raise RuntimeError(
                "segment_offset_to_ida_addr is only valid in 'segments' mode."
            )
        return self.imagebase + seg_offset

    def ida_addr_to_segment_offset(self, ida_addr: int) -> int:
        if self.mode != self.LoadMode.SEGMENTS:
            raise RuntimeError(
                "ida_addr_to_segment_offset is only valid in 'segments' mode."
            )
        return ida_addr - self.imagebase


@dataclasses.dataclass
class SigMakerConfig:
    output_format: SignatureType
    wildcard_operands: bool
    continue_outside_of_function: bool
    wildcard_optimized: bool
    ask_longer_signature: bool = True
    print_top_x: int = 5
    max_single_signature_length: int = 100
    max_xref_signature_length: int = 250


@dataclasses.dataclass(slots=True, frozen=True, repr=False)
class Match:
    address: int

    def __repr__(self) -> str:
        return f"Match(address={hex(self.address)})"

    def __str__(self) -> str:
        return hex(self.address)

    def __int__(self) -> int:
        return self.address

    __index__ = __int__


class SignatureType(enum.Enum):
    IDA = "ida"
    x64Dbg = "x64dbg"
    Mask = "mask"
    BitMask = "bitmask"

    @classmethod
    def at(cls, index: int) -> "SignatureType":
        return list(cls.__members__.values())[index]


class GenerationStatus(enum.Enum):
    """How a GeneratedSignature should be interpreted."""

    UNIQUE = "unique"
    PARTIAL_ON_CANCEL = "partial_on_cancel"


class SignatureByte(typing.NamedTuple):
    value: int
    is_wildcard: bool


class Signature(list[SignatureByte]):
    def add_byte_to_signature(self, address: int, is_wildcard: bool) -> None:
        byte_value = idaapi.get_byte(address)
        self.append(SignatureByte(byte_value, is_wildcard))

    def add_bytes_to_signature(
        self, address: int, count: int, is_wildcard: bool
    ) -> None:
        bytes_data = idaapi.get_bytes(address, count)
        if bytes_data:
            self.extend(SignatureByte(b, is_wildcard) for b in bytes_data)

    def trim_signature(self) -> None:
        n = len(self)
        while n > 0 and self[n - 1].is_wildcard:
            n -= 1
        del self[n:]

    def __str__(self) -> str:
        return self.__format__("")

    def __format__(self, format_spec: str) -> str:
        spec = format_spec.lower()
        try:
            formatter = FORMATTER_MAP[SignatureType(spec)]
        except KeyError:
            raise ValueError(
                f"Unknown format code '{format_spec}' for object of type 'Signature'"
            )
        return formatter.format(self)


class SignatureFormatter(typing.Protocol):
    def format(self, signature: "Signature") -> str: ...


@dataclasses.dataclass(frozen=True, slots=True)
class IdaFormatter:
    wildcard_byte: str = "?"

    def format(self, signature: "Signature") -> str:
        parts = []
        for byte in signature:
            if byte.is_wildcard:
                parts.append(self.wildcard_byte)
            else:
                parts.append(f"{byte.value:02X}")
        return " ".join(parts)


@dataclasses.dataclass(frozen=True, slots=True)
class X64DbgFormatter(IdaFormatter):
    wildcard_byte: str = "??"


@dataclasses.dataclass(frozen=True, slots=True)
class MaskedBytesFormatter:
    wildcard_byte: str = "\\x00"
    mask: str = "x"
    wildcard_mask: str = "?"

    @staticmethod
    def build_signature_parts(
        signature: "Signature",
        byte_format: str,
        wildcard_byte: str,
        mask_char: str,
        wildcard_mask_char: str,
    ) -> tuple[list[str], list[str]]:
        pattern_parts = []
        mask_parts = []
        for byte in signature:
            if byte.is_wildcard:
                pattern_parts.append(wildcard_byte)
                mask_parts.append(wildcard_mask_char)
            else:
                pattern_parts.append(byte_format.format(byte.value))
                mask_parts.append(mask_char)
        return pattern_parts, mask_parts

    def format(self, signature: "Signature") -> str:
        pattern_parts, mask_parts = self.build_signature_parts(
            signature,
            "\\x{:02X}",
            self.wildcard_byte,
            self.mask,
            self.wildcard_mask,
        )
        return "".join(pattern_parts) + " " + "".join(mask_parts)


@dataclasses.dataclass(frozen=True, slots=True)
class ByteArrayBitmaskFormatter:
    wildcard_byte: str = "0x00"
    mask: str = "1"
    wildcard_mask: str = "0"

    def format(self, signature: "Signature") -> str:
        pattern_parts, mask_parts = MaskedBytesFormatter.build_signature_parts(
            signature,
            "0x{:02X}",
            self.wildcard_byte,
            self.mask,
            self.wildcard_mask,
        )
        pattern_str = ", ".join(pattern_parts)
        mask_str = "".join(mask_parts)[::-1]
        return f"{pattern_str} 0b{mask_str}"


FORMATTER_MAP: typing.Dict[SignatureType, SignatureFormatter] = {
    SignatureType.IDA: IdaFormatter(),
    SignatureType.x64Dbg: X64DbgFormatter(),
    SignatureType.Mask: MaskedBytesFormatter(),
    SignatureType.BitMask: ByteArrayBitmaskFormatter(),
}


@dataclasses.dataclass(slots=True, frozen=True)
class WildcardPolicy:
    allowed_types: frozenset[int]
    _ctx = WILDCARD_POLICY_CTX

    class RarelyWildcardable(enum.IntEnum):
        VOID = idaapi.o_void
        REG = idaapi.o_reg

    class BaseKind(enum.IntEnum):
        MEM = idaapi.o_mem
        PHRASE = idaapi.o_phrase
        DISPL = idaapi.o_displ
        IMM = idaapi.o_imm
        FAR = idaapi.o_far
        NEAR = idaapi.o_near

    class X86Kind(enum.IntEnum):
        TRREG = idaapi.o_idpspec0
        DBREG = idaapi.o_idpspec1
        CRREG = idaapi.o_idpspec2
        FPREG = idaapi.o_idpspec3
        MMX = idaapi.o_idpspec4
        XMM = idaapi.o_idpspec5
        YMM = idaapi.o_idpspec5 + 1
        ZMM = idaapi.o_idpspec5 + 2
        KREG = idaapi.o_idpspec5 + 3

    class ARMKind(enum.IntEnum):
        REGLIST = idaapi.o_idpspec1
        CREGLIST = idaapi.o_idpspec2
        CREG = idaapi.o_idpspec3
        FPREGLIST = idaapi.o_idpspec4
        TEXT = idaapi.o_idpspec5
        COND = idaapi.o_idpspec5 + 1

    class MIPSKind(enum.IntEnum):
        pass

    class PPCKind(enum.IntEnum):
        SPR = idaapi.o_idpspec0
        TWOFPR = idaapi.o_idpspec1
        SHMBME = idaapi.o_idpspec2
        CRF = idaapi.o_idpspec3
        CRB = idaapi.o_idpspec4
        DCR = idaapi.o_idpspec5

    @dataclasses.dataclass(slots=True)
    class _Use:
        policy: "WildcardPolicy"
        policy_class: type["WildcardPolicy"]
        token: contextvars.Token | None = None

        def __enter__(self):
            self.token = self.policy_class.set_current(self.policy)
            return self.policy

        def __exit__(self, exc_type, exc, tb):
            if self.token is not None:
                self.policy_class.reset_current(self.token)

    @classmethod
    def for_x86(cls) -> "WildcardPolicy":
        # Exclude BaseKind.IMM. An immediate like the 0x13371338 in
        # `mov rcx, 0x13371338` is a literal value baked into the
        # instruction encoding; it does not shift between binary builds,
        # so wildcarding it only removes bytes that would have made the
        # signature unique. MEM/FAR/NEAR still get wildcarded because
        # those operands DO encode addresses that move between builds.
        x86_base = frozenset(cls.BaseKind) - {cls.BaseKind.IMM}
        return cls(x86_base | frozenset(cls.X86Kind))

    @classmethod
    def for_arm(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind) | frozenset(cls.ARMKind))

    @classmethod
    def for_mips(cls) -> "WildcardPolicy":
        return cls(frozenset({cls.BaseKind.MEM, cls.BaseKind.FAR, cls.BaseKind.NEAR}))

    @classmethod
    def for_ppc(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind) | frozenset(cls.PPCKind))

    @classmethod
    def default_generic(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind))

    @classmethod
    def detect_from_processor(cls) -> "WildcardPolicy":
        arch = idaapi.ph_get_id()
        if arch == idaapi.PLFM_386:
            return cls.for_x86()
        if arch == idaapi.PLFM_ARM:
            return cls.for_arm()
        if arch == idaapi.PLFM_MIPS:
            return cls.for_mips()
        if arch == idaapi.PLFM_PPC:
            return cls.for_ppc()
        return cls.default_generic()

    def allows_type(self, op_type: int) -> bool:
        return op_type in self.allowed_types

    def to_mask(self) -> int:
        return sum(1 << int(t) for t in self.allowed_types)

    @classmethod
    def from_mask(cls, mask: int) -> "WildcardPolicy":
        types = {t for t in range(0, 64) if (mask >> t) & 1}
        return cls(frozenset(types))

    @classmethod
    def current(cls) -> "WildcardPolicy":
        policy = cls._ctx.get(cls.detect_from_processor())
        cls._ctx.set(policy)
        return policy

    @classmethod
    def set_current(cls, policy: "WildcardPolicy") -> contextvars.Token:
        return cls._ctx.set(policy)

    @classmethod
    def reset_current(cls, token: contextvars.Token) -> None:
        cls._ctx.reset(token)

    @classmethod
    def use(cls, policy: "WildcardPolicy") -> "WildcardPolicy._Use":
        return cls._Use(policy, cls)


@dataclasses.dataclass(slots=True, frozen=True)
class GeneratedSignature:
    """Result container for signature generation operations."""

    signature: Signature
    address: Match | None = None
    status: GenerationStatus = GenerationStatus.UNIQUE
    match_count: int | None = None

    def _wildcard_count(self) -> int:
        """Number of wildcard bytes in this signature."""
        return sum(1 for b in self.signature if b.is_wildcard)

    def __lt__(self, other) -> bool:
        if not isinstance(other, GeneratedSignature):
            return NotImplemented
        # Prefer shorter signatures; break ties by fewer wildcards so the
        # most specific signature wins among equal-length candidates.
        return (len(self.signature), self._wildcard_count()) < (
            len(other.signature),
            other._wildcard_count(),
        )


@dataclasses.dataclass(slots=True)
class XrefGeneratedSignature:
    signatures: list[GeneratedSignature]


class SigText:
    _HEX_SET = frozenset(string.hexdigits)
    _TRANS = str.maketrans(
        {
            ",": " ",
            ";": " ",
            ":": " ",
            "|": " ",
            "_": " ",
            "-": " ",
            "\t": " ",
            "\n": " ",
            "\r": " ",
            ".": "?",
        }
    )

    @staticmethod
    def _tok_is_hex(s: str) -> bool:
        return len(s) > 0 and all(c in SigText._HEX_SET for c in s)

    @staticmethod
    def _split_hex_pairs(s: str) -> list[str]:
        return [s[i : i + 2].upper() for i in range(0, len(s), 2)]

    @staticmethod
    def normalize(sig_str: str) -> tuple[str, list[tuple[int, bool]]]:
        if not sig_str:
            return "", []
        s = sig_str.translate(SigText._TRANS)
        raw = [t for t in s.split() if t]
        toks: list[str] = []
        for t in raw:
            t = t.strip()
            if t.startswith(("0x", "0X")):
                t = t[2:]
            if not t:
                continue
            toks.append(t)

        out: list[str] = []
        i = 0
        while i < len(toks):
            t = toks[i]

            if t == "??":
                out.append("??")
                i += 1
                continue

            if len(t) == 2 and SigText._tok_is_hex(t):
                out.append(t.upper())
                i += 1
                continue

            if len(t) == 1 and t in SigText._HEX_SET:
                out.append((t + "?").upper())
                i += 1
                continue

            if t == "?":
                out.append("??")
                i += 1
                continue

            if SigText._tok_is_hex(t):
                if (len(t) & 1) != 0:
                    pairs = SigText._split_hex_pairs(t)
                    pairs_len = len(pairs)
                    if pairs and len(pairs[pairs_len - 1]) == 1:
                        pairs[pairs_len - 1] = "?" + pairs[pairs_len - 1]
                    out.extend(pairs)
                    i += 1
                    continue
                else:
                    out.extend(SigText._split_hex_pairs(t))
                    i += 1
                    continue

            if len(t) == 2:
                hi, lo = t[0], t[1]
                if (hi in SigText._HEX_SET or hi == "?") and (
                    lo in SigText._HEX_SET or lo == "?"
                ):
                    out.append((hi + lo).upper())
                    i += 1
                    continue

            raise ValueError(f"invalid signature token: {t!r}")

        pattern: list[tuple[int, bool]] = []
        for tok in out:
            hi, lo = tok[0], tok[1]
            wild = (hi == "?") or (lo == "?")
            hv = 0 if hi == "?" else int(hi, 16)
            lv = 0 if lo == "?" else int(lo, 16)
            pattern.append(((hv << 4) | lv, wild))

        return " ".join(out), pattern


class OperandProcessor:
    def __init__(self):
        self._is_arm = self._check_is_arm()

    @staticmethod
    def _check_is_arm() -> bool:
        return idaapi.ph_get_id() == idaapi.PLFM_ARM

    def _get_operand_offset_arm(
        self, ins: idaapi.insn_t, off: typing.List[int], length: typing.List[int]
    ) -> bool:
        policy = WildcardPolicy.current()
        for op in ins:
            if op.type in policy.allowed_types:
                off[0] = op.offb
                length[0] = 3 if ins.size == 4 else (7 if ins.size == 8 else 0)
                return True
        return False

    def get_operand(
        self,
        ins: idaapi.insn_t,
        off: typing.List[int],
        length: typing.List[int],
        wildcard_optimized: bool,
    ) -> bool:
        policy = WildcardPolicy.current()
        if self._is_arm:
            return self._get_operand_offset_arm(ins, off, length)
        for op in ins:
            if op.type == idaapi.o_void:
                continue
            if not policy.allows_type(op.type):
                continue
            if op.offb == 0 and not wildcard_optimized:
                continue
            off[0] = op.offb
            length[0] = ins.size - op.offb
            return True
        return False


class InstructionProcessor:
    def __init__(self, operand_processor: OperandProcessor):
        self.operand_processor = operand_processor

    def append_instruction_to_sig(
        self,
        sig: Signature,
        ea: int,
        ins: idaapi.insn_t,
        wildcard_operands: bool,
        wildcard_optimized: bool,
    ) -> None:
        if not wildcard_operands:
            sig.add_bytes_to_signature(ea, ins.size, is_wildcard=False)
            return

        off, length = [0], [0]
        has_operand = self.operand_processor.get_operand(
            ins, off, length, wildcard_optimized
        )
        if not has_operand or length[0] <= 0:
            sig.add_bytes_to_signature(ea, ins.size, is_wildcard=False)
            return

        if off[0] > 0:
            sig.add_bytes_to_signature(ea, off[0], is_wildcard=False)

        sig.add_bytes_to_signature(ea + off[0], length[0], is_wildcard=True)

        remaining_len = ins.size - (off[0] + length[0])
        if remaining_len > 0:
            sig.add_bytes_to_signature(
                ea + off[0] + length[0], remaining_len, is_wildcard=False
            )


@dataclasses.dataclass(slots=True)
class InstructionWalker:
    start_ea: int
    end_ea: int = idaapi.BADADDR

    cursor: int = dataclasses.field(init=False)
    _instruction: idaapi.insn_t = dataclasses.field(
        init=False, repr=False, default_factory=idaapi.insn_t
    )

    def __post_init__(self):
        if self.start_ea == idaapi.BADADDR:
            raise ValueError("Invalid start address for InstructionWalker")
        self.cursor = self.start_ea

    def __iter__(self):
        self.cursor = self.start_ea
        return self

    def __next__(self) -> tuple[int, idaapi.insn_t, int]:
        if self.end_ea != idaapi.BADADDR and self.cursor >= self.end_ea:
            raise StopIteration

        current_instruction_ea = self.cursor
        ins_len = idaapi.decode_insn(self._instruction, current_instruction_ea)

        if ins_len <= 0:
            raise StopIteration

        self.cursor += ins_len

        return current_instruction_ea, self._instruction, ins_len


class UniqueSignatureGenerator:
    def __init__(self, processor: InstructionProcessor):
        self.processor = processor

    def generate(self, ea: int, cfg: SigMakerConfig) -> Signature:
        if not is_address_marked_as_code(ea):
            raise Unexpected("Cannot create code signature for data")

        sig = Signature()
        start_fn = idaapi.get_func(ea)
        bytes_since_last_check = 0

        # Seed-and-refine (issue #398): on the compiled SIMD path, scan the
        # image once to seed a candidate offset set, then refine that set in
        # memory as the pattern grows instead of rebuilding the whole image
        # buffer on every uniqueness check. Without the SIMD module we fall back
        # to idaapi.bin_search, which never materializes a buffer (is_unique
        # bails at the second match). The seed is built at most once per
        # generate().
        offsets: typing.Optional[list[int]] = None  # SIMD list candidates
        buf: typing.Optional["InMemoryBuffer"] = None

        for cur_ea, ins, ins_len in InstructionWalker(ea):
            if bytes_since_last_check > cfg.max_single_signature_length:
                if not cfg.ask_longer_signature:
                    raise Unexpected("Signature not unique within length constraints")
                bytes_since_last_check = 0

            if (
                not cfg.continue_outside_of_function
                and start_fn
                and cur_ea >= start_fn.end_ea
            ):
                raise Unexpected("Signature left function scope without being unique")

            prev_len = len(sig)
            self.processor.append_instruction_to_sig(
                sig, cur_ea, ins, cfg.wildcard_operands, cfg.wildcard_optimized
            )
            bytes_since_last_check += ins_len

            if SIMD_SPEEDUP_AVAILABLE:
                # Compiled SIMD: seed once via a single image load, then refine
                # the surviving offsets in memory per appended byte.
                if offsets is None:
                    offsets, buf = SignatureSearcher.find_all_offsets(f"{sig:ida}")
                else:
                    data_mv = buf.data()
                    for j in range(prev_len, len(sig)):
                        sb = sig[j]
                        mask = 0x00 if sb.is_wildcard else 0xFF
                        offsets = _refine_offsets(data_mv, offsets, j, sb.value, mask)
                if len(offsets) == 1:
                    sig.trim_signature()
                    return sig
                continue

            # Native bin_search fallback: is_unique bails at the 2nd match and
            # never materializes a buffer.
            if SignatureSearcher.is_unique(f"{sig:ida}"):
                sig.trim_signature()
                return sig

        raise Unexpected("Signature not unique (reached end of analysis)")


# ---------------------------------------------------------------------------
# Function-wide signature search (shortest unique signature anywhere in a func)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(slots=True, frozen=True)
class _DecodedInstruction:
    """Pre-decoded instruction data; produced once per function and reused
    across anchor growth loops in MinimalFunctionSignatureGenerator.

    operand_offb / operand_length describe the byte range to wildcard for
    this cfg's operand policy. Both are 0 when no operand should be
    wildcarded (e.g. wildcard_operands=False, or the instruction has no
    operand that matches the current WildcardPolicy).
    """

    ea: int
    size: int
    raw_bytes: bytes
    operand_offb: int
    operand_length: int


def _refine_offsets(
    data_mv: memoryview,
    offsets: list[int],
    j: int,
    value: int,
    mask: int,
) -> list[int]:
    """Keep offsets c where (data_mv[c + j] & mask) == (value & mask).

    j is the pattern-relative index of the byte being checked; c is a match
    start offset into data_mv. Candidates whose c + j runs past the buffer
    cannot match and are dropped. Used to refine a shrinking candidate set as
    a signature grows, instead of re-scanning the whole database.
    """
    n = len(data_mv)
    target = value & mask
    return [c for c in offsets if c + j < n and (data_mv[c + j] & mask) == target]


def _refine_offsets_into(
    data_mv: memoryview,
    cands: "array.array",
    count: int,
    j: int,
    value: int,
    mask: int,
) -> int:
    """Refine the first ``count`` entries of the uint32 array ``cands`` in
    place (Cython when available), returning the new count. The Python branch
    is a defensive fallback that mirrors _refine_offsets.
    """
    if SIMD_SPEEDUP_AVAILABLE:
        return simd_scan.refine_offsets(data_mv, cands, count, j, value, mask)
    n = len(data_mv)
    target = value & mask
    w = 0
    for r in range(count):
        c = cands[r]
        if c + j < n and (data_mv[c + j] & mask) == target:
            cands[w] = cands[r]
            w += 1
    return w


@dataclasses.dataclass(frozen=True, slots=True)
class _ByteIndex:
    """A 2-byte bucket position index over the segment buffer.

    Wraps simd_scan.build_byte_index. Built once per generate() and discarded;
    reused across all anchors in that one search. Returns None unless a
    compiled SIMD speedup module that exposes build_byte_index is present.
    """

    heads: "array.array"
    positions: "array.array"

    @classmethod
    def build(cls, data_mv: memoryview) -> typing.Optional["_ByteIndex"]:
        if not SIMD_SPEEDUP_AVAILABLE or len(data_mv) < 2:
            return None
        build_byte_index = getattr(simd_scan, "build_byte_index", None)
        if build_byte_index is None:
            return None
        heads, positions = build_byte_index(data_mv)
        return cls(heads, positions)

    def bucket_size(self, key: int) -> int:
        return self.heads[key + 1] - self.heads[key]

    def candidates(self, key: int) -> "array.array":
        return self.positions[self.heads[key]:self.heads[key + 1]]

    def bucket_size1(self, b: int) -> int:
        # 1-byte bucket for b: all 2-byte keys (b<<8)..((b+1)<<8 - 1) telescope
        # into one contiguous range.
        return self.heads[(b + 1) << 8] - self.heads[b << 8]

    def candidates1(self, b: int) -> "array.array":
        return self.positions[self.heads[b << 8]:self.heads[(b + 1) << 8]]


def _select_seed_run(
    sig: "Signature", index: "_ByteIndex"
) -> typing.Optional[tuple[int, int, int]]:
    """Pick the unmasked run (2-byte or single byte) with the smallest index
    bucket (Dynamic Seed Selection), returning (offset, width, key).

    Returns None only when sig has no exact byte at all.
    """
    best: typing.Optional[tuple[int, int, int, int]] = None  # (size, offset, width, key)
    m = len(sig)
    for j in range(m - 1):
        a = sig[j]
        b = sig[j + 1]
        if a.is_wildcard or b.is_wildcard:
            continue
        key = (a.value << 8) | b.value
        size = index.bucket_size(key)
        if best is None or size < best[0]:
            best = (size, j, 2, key)
    for j in range(m):
        sb = sig[j]
        if sb.is_wildcard:
            continue
        size = index.bucket_size1(sb.value)
        if best is None or size < best[0]:
            best = (size, j, 1, sb.value)
    if best is None:
        return None
    return best[1], best[2], best[3]


def _seed_via_index(
    sig: "Signature",
    index: typing.Optional["_ByteIndex"],
    buf: "InMemoryBuffer",
) -> typing.Optional[tuple["array.array", int]]:
    """Seed the candidate set from the byte index instead of scanning.

    Picks the most selective unmasked run via Dynamic Seed Selection, maps its
    hits back to candidate pattern-starts, and refines against the rest of the
    pattern so the result equals matches(full pattern). Returns
    (candidates_array, count), or None if the index is unavailable or the
    pattern has no exact byte at all (caller falls back to a scan).
    """
    if index is None:
        return None
    run = _select_seed_run(sig, index)
    if run is None:
        return None
    s, width, key = run
    data_mv = buf.data()
    n = len(data_mv)
    m = len(sig)
    raw = index.candidates(key) if width == 2 else index.candidates1(key)
    cands = array.array("I", (p - s for p in raw if p >= s and (p - s) + m <= n))
    # candidates1 is derived from 2-byte windows and never sees offset n-1 as a
    # window start, so add a final-byte hit explicitly and let refine validate.
    if width == 1 and n >= 1 and data_mv[n - 1] == key:
        p = n - 1 - s
        if 0 <= p and p + m <= n:
            cands.append(p)
    count = len(cands)
    seed_span = (s, s + 1) if width == 2 else (s,)
    for j in range(m):
        if j in seed_span:
            continue
        sb = sig[j]
        if sb.is_wildcard:
            continue
        count = _refine_offsets_into(data_mv, cands, count, j, sb.value, 0xFF)
    return cands, count


def _decode_function_for_anchors(
    pfn: "idaapi.func_t",
    processor: "InstructionProcessor",
    cfg: "SigMakerConfig",
) -> list[_DecodedInstruction]:
    """Decode a function's instructions once and capture per-instruction data
    for use across all anchor growth loops.

    Reads all function bytes via one idaapi.get_bytes call, then walks
    instructions via InstructionWalker. The operand wildcard decision is baked
    in based on cfg.wildcard_operands / cfg.wildcard_optimized; operand_offb /
    operand_length are both 0 when no operand should be wildcarded.
    """
    total = pfn.end_ea - pfn.start_ea
    if total <= 0:
        return []
    func_bytes = idaapi.get_bytes(pfn.start_ea, total)
    if not func_bytes:
        return []

    decoded: list[_DecodedInstruction] = []
    for ea, ins, ins_len in InstructionWalker(pfn.start_ea, pfn.end_ea):
        offset = ea - pfn.start_ea
        if offset < 0 or offset + ins_len > len(func_bytes):
            break
        raw = bytes(func_bytes[offset:offset + ins_len])

        operand_offb = 0
        operand_length = 0
        if cfg.wildcard_operands:
            off, length = [0], [0]
            if processor.operand_processor.get_operand(
                ins, off, length, cfg.wildcard_optimized
            ):
                operand_offb = off[0]
                operand_length = length[0]

        decoded.append(_DecodedInstruction(
            ea=ea,
            size=ins_len,
            raw_bytes=raw,
            operand_offb=operand_offb,
            operand_length=operand_length,
        ))
    return decoded


class MinimalFunctionSignatureGenerator:
    """Find the shortest unique signature anywhere within a function body.

    Decodes the function once at the start of generate(), then iterates every
    instruction as a possible anchor over the pre-decoded list, growing a
    signature from each until unique (bounded by function end and by the size
    of the best candidate found so far). Returns the smallest unique signature
    with the fewest wildcards. Raises Unexpected if no unique signature exists
    within the function.

    The wait-box/ProgressBox UI from upstream is intentionally omitted; this
    runs headless inside the MCP server. An optional progress_reporter may be
    supplied to support cooperative cancellation.
    """

    MIN_USEFUL_SIG_BYTES = 5

    def __init__(
        self,
        processor: InstructionProcessor,
        progress_reporter: typing.Optional[ProgressReporter] = None,
    ):
        self.processor = processor
        self.progress_reporter = progress_reporter

    def generate(
        self, pfn: "idaapi.func_t", cfg: SigMakerConfig
    ) -> GeneratedSignature:
        """Search the function body for the shortest unique signature.

        Uses cfg.max_single_signature_length as the initial budget; the budget
        shrinks monotonically as better candidates are found. Raises Unexpected
        if no start point produces a unique signature within the length budget
        (or all candidates are degenerate, < MIN_USEFUL_SIG_BYTES bytes).
        """
        candidates: list[GeneratedSignature] = []

        decoded = _decode_function_for_anchors(pfn, self.processor, cfg)
        if not decoded:
            raise Unexpected("No unique signature within function")

        # Load the segment buffer once and reuse it across every is_unique
        # call (only meaningful on the SIMD path).
        buf: typing.Optional["InMemoryBuffer"] = None
        index: typing.Optional["_ByteIndex"] = None
        if SIMD_SPEEDUP_AVAILABLE:
            buf = InMemoryBuffer.load(mode=InMemoryBuffer.LoadMode.SEGMENTS)
            index = _ByteIndex.build(buf.data())

        best_size = cfg.max_single_signature_length
        for anchor_idx, di in enumerate(decoded):
            if (
                self.progress_reporter is not None
                and self.progress_reporter.should_cancel()
            ):
                raise UserCanceledError("Function signature search canceled by user")

            sig = self._grow_unique_from_decoded(
                decoded, anchor_idx, best_size, cfg, buf=buf, index=index
            )
            if sig is None:
                continue
            if len(sig) < self.MIN_USEFUL_SIG_BYTES:
                continue

            candidates.append(GeneratedSignature(sig, Match(di.ea)))
            best_size = min(best_size, len(sig))

            wildcard_count = sum(1 for b in sig if b.is_wildcard)
            if len(sig) <= self.MIN_USEFUL_SIG_BYTES and wildcard_count == 0:
                break

        if not candidates:
            raise Unexpected("No unique signature within function")

        candidates.sort()
        return candidates[0]

    def _grow_unique_from_decoded(
        self,
        decoded: list[_DecodedInstruction],
        anchor_idx: int,
        max_len: int,
        cfg: SigMakerConfig,
        buf: typing.Optional["InMemoryBuffer"] = None,
        index: typing.Optional["_ByteIndex"] = None,
    ) -> typing.Optional[Signature]:
        """Grow a signature from ``decoded[anchor_idx]`` forward until unique.

        On the SIMD path it seeds an in-memory candidate-offset set that is
        refined per appended byte, so the database is scanned once per anchor
        rather than once per growth step. On non-SIMD builds it falls back to a
        per-step is_unique scan (which bails at the second match).
        """
        sig = Signature()
        offsets: typing.Optional["array.array"] = None
        ocount = 0
        seed_buf = buf
        min_useful = self.MIN_USEFUL_SIG_BYTES
        for i in range(anchor_idx, len(decoded)):
            if (
                self.progress_reporter is not None
                and self.progress_reporter.should_cancel()
            ):
                raise UserCanceledError("Function signature search canceled by user")

            prev_len = len(sig)
            self._append_decoded_to_sig(sig, decoded[i])

            if len(sig) > max_len:
                return None

            # Below MIN_USEFUL_SIG_BYTES a seed scan would enumerate every match
            # of a short, common prefix only for the caller to discard the
            # result. Probe uniqueness cheaply (bail-at-2) and defer the
            # seed-and-refine until the pattern is long enough to be useful.
            if len(sig) < min_useful:
                if SignatureSearcher.is_unique(f"{sig:ida}", buf=buf):
                    sig.trim_signature()
                    return sig
                continue

            if not SIMD_SPEEDUP_AVAILABLE or seed_buf is None:
                count = SignatureSearcher.count_matches(f"{sig:ida}", buf=buf)
            elif offsets is None:
                seeded = _seed_via_index(sig, index, seed_buf)
                if seeded is None:
                    lst, seed_buf = SignatureSearcher.find_all_offsets(
                        f"{sig:ida}", buf=seed_buf
                    )
                    offsets = array.array("I", lst)
                    ocount = len(offsets)
                else:
                    offsets, ocount = seeded
                count = ocount
            else:
                data_mv = seed_buf.data()
                for j in range(prev_len, len(sig)):
                    sb = sig[j]
                    mask = 0x00 if sb.is_wildcard else 0xFF
                    ocount = _refine_offsets_into(
                        data_mv, offsets, ocount, j, sb.value, mask
                    )
                count = ocount

            if count == 1:
                sig.trim_signature()
                return sig

        return None

    def _append_decoded_to_sig(
        self, sig: Signature, di: _DecodedInstruction
    ) -> None:
        """Append a pre-decoded instruction's bytes to ``sig``, honoring its
        baked operand-wildcard decision. Mirrors
        InstructionProcessor.append_instruction_to_sig but reads from
        di.raw_bytes instead of calling idaapi.get_bytes.
        """
        raw = di.raw_bytes
        if di.operand_length <= 0:
            sig.extend(SignatureByte(b, False) for b in raw)
            return

        end_operand = di.operand_offb + di.operand_length
        sig.extend(SignatureByte(b, False) for b in raw[:di.operand_offb])
        sig.extend(SignatureByte(b, True) for b in raw[di.operand_offb:end_operand])
        sig.extend(SignatureByte(b, False) for b in raw[end_operand:])


class RangeSignatureGenerator:
    def __init__(self, processor: InstructionProcessor):
        self.processor = processor

    def generate(self, start_ea: int, end_ea: int, cfg: SigMakerConfig) -> Signature:
        sig = Signature()

        if not is_address_marked_as_code(start_ea):
            sig.add_bytes_to_signature(start_ea, end_ea - start_ea, is_wildcard=False)
            return sig

        walker = InstructionWalker(start_ea, end_ea)
        for cur_ea, ins, _ in walker:
            self.processor.append_instruction_to_sig(
                sig, cur_ea, ins, cfg.wildcard_operands, cfg.wildcard_optimized
            )

        if walker.cursor < end_ea:
            remaining_bytes = end_ea - walker.cursor
            sig.add_bytes_to_signature(
                walker.cursor, remaining_bytes, is_wildcard=False
            )

        sig.trim_signature()
        return sig


@dataclasses.dataclass(slots=True)
class SignatureMaker:
    _operand_processor: OperandProcessor = dataclasses.field(
        default_factory=OperandProcessor
    )

    _instruction_processor: InstructionProcessor = dataclasses.field(init=False)
    _unique_generator: UniqueSignatureGenerator = dataclasses.field(init=False)
    _range_generator: RangeSignatureGenerator = dataclasses.field(init=False)
    _function_generator: MinimalFunctionSignatureGenerator = dataclasses.field(
        init=False
    )

    def __post_init__(self):
        self._instruction_processor = InstructionProcessor(self._operand_processor)
        self._unique_generator = UniqueSignatureGenerator(self._instruction_processor)
        self._range_generator = RangeSignatureGenerator(self._instruction_processor)
        self._function_generator = MinimalFunctionSignatureGenerator(
            self._instruction_processor
        )

    def make_signature(
        self, ea: int | Match, cfg: SigMakerConfig, end: int | None = None
    ) -> GeneratedSignature:
        start_ea = int(ea)
        if start_ea == idaapi.BADADDR:
            raise Unexpected("Invalid start address")

        if end is None:
            sig = self._unique_generator.generate(start_ea, cfg)
            return GeneratedSignature(sig, Match(start_ea))

        if end <= start_ea:
            raise Unexpected("End address must be after start address")

        sig = self._range_generator.generate(start_ea, end, cfg)
        return GeneratedSignature(sig)

    def make_function_signature(
        self, pfn: "idaapi.func_t", cfg: SigMakerConfig
    ) -> GeneratedSignature:
        """Find the shortest unique signature anywhere inside ``pfn``.

        Unlike make_signature(func.start_ea, ...), which anchors at the
        function entry, this scans every instruction in the body as a possible
        anchor and returns the shortest unique signature found. The returned
        GeneratedSignature's ``address`` is the anchor it starts from, which
        may be mid-function.
        """
        return self._function_generator.generate(pfn, cfg)


class XrefFinder:
    """Handles finding and generating signatures for XREF addresses."""

    def __init__(self):
        self.signature_maker = SignatureMaker()

    @classmethod
    def iter_code_xrefs_to(cls, ea: int) -> typing.Iterable[int]:
        xb = idaapi.xrefblk_t()
        if not xb.first_to(ea, idaapi.XREF_ALL):
            return

        while True:
            if is_address_marked_as_code(xb.frm):
                yield xb.frm
            if not xb.next_to():
                break

    @classmethod
    def count_code_xrefs_to(cls, ea: int) -> int:
        return sum(1 for _ in cls.iter_code_xrefs_to(ea))

    def find_xrefs(self, ea: int, cfg: SigMakerConfig) -> XrefGeneratedSignature:
        xref_signatures: list[GeneratedSignature] = []

        total = self.count_code_xrefs_to(ea)
        if total == 0:
            return XrefGeneratedSignature([])

        cfg_no_prompt = dataclasses.replace(cfg, ask_longer_signature=False)

        shortest_len = cfg.max_xref_signature_length + 1

        for i, frm_ea in enumerate(self.iter_code_xrefs_to(ea), start=1):
            try:
                result = self.signature_maker.make_signature(frm_ea, cfg_no_prompt)
                sig: typing.Optional[Signature] = result.signature
            except Exception:
                sig = None

            if sig is None:
                continue

            if len(sig) < shortest_len:
                shortest_len = len(sig)
            xref_signatures.append(GeneratedSignature(sig, Match(frm_ea)))

        xref_signatures.sort()
        return XrefGeneratedSignature(xref_signatures)


@dataclasses.dataclass(slots=True)
class SearchResults:
    matches: list[Match]
    signature_str: str


class SignatureParser:
    _HEX_PAIR = re.compile(r"^[0-9A-Fa-f]{2}$")
    _ESCAPED_HEX = re.compile(r"\\x[0-9A-Fa-f]{2}")
    _RUN_0X = re.compile(r"(?:0x[0-9A-Fa-f]{2})+")

    _MASK_REGEX = re.compile(r"x(?:x|\?)+")
    _BINARY_MASK_REGEX = re.compile(r"0b[01]+")

    @classmethod
    def parse(cls, input_str: str) -> str:
        mask = cls._extract_mask(input_str)
        parsed = ""
        if mask:
            bytestr: list[str] = []
            if (bytestr := cls._ESCAPED_HEX.findall(input_str)) and len(bytestr) == len(
                mask
            ):
                parsed = cls._masked_bytes_to_ida(bytestr, mask, slice_from=2)

            elif (bytestr := cls._RUN_0X.findall(input_str)) and len(bytestr) == len(
                mask
            ):
                parsed = cls._masked_bytes_to_ida(bytestr, mask, slice_from=2)
            else:
                LOGGER.warning(
                    f'Detected mask "{mask}" but failed to match corresponding bytes'
                )
        else:
            parsed = cls._normalize_loose_hex(input_str)
        return parsed.strip()

    @classmethod
    def _extract_mask(cls, s: str) -> str:
        m = cls._MASK_REGEX.search(s)
        if m:
            return m.group(0)

        m = cls._BINARY_MASK_REGEX.search(s)
        if not m:
            return ""
        bits = m.group(0)[2:]
        return "".join("x" if b == "1" else "?" for b in bits[::-1])

    @staticmethod
    def _masked_bytes_to_ida(
        byte_tokens: list[str], mask: str, *, slice_from: int
    ) -> str:
        sig = Signature(
            [
                SignatureByte(int(tok[slice_from:], 16), mask[i] == "?")
                for i, tok in enumerate(byte_tokens)
            ]
        )
        return f"{sig:ida}"

    @classmethod
    def _normalize_loose_hex(cls, input_str: str) -> str:
        s = input_str
        s = re.sub(r"[\)\(\[\]]+", "", s)
        s = re.sub(r"^\s+", "", s)
        s = re.sub(r"[? ]+$", "", s) + " "
        s = re.sub(r"\\?\\x", "", s)
        s = re.sub(r"\s+", " ", s)

        tokens = [t.strip() for t in s.split() if t.strip()]
        out: list[str] = []
        for t in tokens:
            if t == "?" or t == "??":
                out.append("?")
                continue
            if t.lower().startswith("0x"):
                t = t[2:]
            if not cls._HEX_PAIR.match(t):
                out.append("?")
                continue
            out.append(t.upper())

        return (" ".join(out) + " ") if out else ""


@dataclasses.dataclass(slots=True)
class SignatureSearcher:
    input_signature: str = ""

    @classmethod
    def from_signature(cls, input_signature: str) -> "SignatureSearcher":
        return cls(input_signature=input_signature)

    def search(self) -> SearchResults:
        sig_str = SignatureParser.parse(self.input_signature)
        if not sig_str:
            return SearchResults([], "")
        matches = self.find_all(sig_str)
        return SearchResults(matches, sig_str)

    @staticmethod
    def _find_all_simd(
        ida_signature: str,
        skip_more_than_one: bool = False,
        buf: typing.Optional["InMemoryBuffer"] = None,
    ) -> list[Match]:
        simd_signature, _ = SigText.normalize(ida_signature)
        if buf is None:
            buf = InMemoryBuffer.load(mode=InMemoryBuffer.LoadMode.SEGMENTS)
        data_mv = buf.data()

        sig = _SimdSignature(simd_signature)
        results: list[Match] = []
        base = idaapi.inf_get_min_ea()
        if (k := sig.size_bytes) == 0:
            return [Match(base)]

        n = len(data_mv)
        off = 0
        # Poll cancellation every _CANCEL_POLL_STRIDE matches rather than per
        # match: user_cancelled() is not free and a short, common pattern can
        # produce millions of matches.
        since_poll = 0
        while off <= n - k:
            since_poll += 1
            if since_poll >= _CANCEL_POLL_STRIDE:
                since_poll = 0
                if _user_canceled():
                    break
            idx = _simd_scan_bytes(data_mv[off:], sig)
            if idx < 0:
                break
            ea = base + off + idx
            results.append(Match(ea))
            if skip_more_than_one and len(results) > 1:
                break
            off += idx + 1
        return results

    @staticmethod
    def find_all_offsets(
        ida_signature: str,
        buf: typing.Optional["InMemoryBuffer"] = None,
    ) -> tuple[list[int], "InMemoryBuffer"]:
        """Return (offsets, buf): every match as a 0-based offset into
        buf.data(), plus the buffer used. The offsets seed an in-memory
        refinement; reusing the returned buf keeps subsequent refinement on
        the same bytes. SIMD path only.
        """
        simd_signature, _ = SigText.normalize(ida_signature)
        if buf is None:
            buf = InMemoryBuffer.load(mode=InMemoryBuffer.LoadMode.SEGMENTS)
        data_mv = buf.data()
        sig = _SimdSignature(simd_signature)
        offsets: list[int] = []
        k = sig.size_bytes
        if k == 0:
            return [0], buf
        n = len(data_mv)
        off = 0
        since_poll = 0
        while off <= n - k:
            since_poll += 1
            if since_poll >= _CANCEL_POLL_STRIDE:
                since_poll = 0
                if _user_canceled():
                    break
            idx = _simd_scan_bytes(data_mv[off:], sig)
            if idx < 0:
                break
            offsets.append(off + idx)
            off += idx + 1
        return offsets, buf

    @staticmethod
    def find_all(
        ida_signature: str,
        buf: typing.Optional["InMemoryBuffer"] = None,
        skip_more_than_one: bool = False,
    ) -> list[Match]:
        if SIMD_SPEEDUP_AVAILABLE:
            return SignatureSearcher._find_all_simd(
                ida_signature, skip_more_than_one=skip_more_than_one, buf=buf
            )
        binary = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(binary, idaapi.inf_get_min_ea(), ida_signature, 16)
        out: list[Match] = []
        ea = idaapi.inf_get_min_ea()
        max_ea = idaapi.inf_get_max_ea()
        _bin_search = getattr(idaapi, "bin_search", None) or getattr(
            idaapi, "bin_search3"
        )
        flags = idaapi.BIN_SEARCH_NOCASE | idaapi.BIN_SEARCH_FORWARD
        while True:
            if _user_canceled():
                break
            hit, _ = _bin_search(ea, max_ea, binary, flags)
            if hit == idaapi.BADADDR:
                break
            out.append(Match(hit))
            # is_unique only needs to know if there is more than one match;
            # bail at 2 instead of enumerating every match in the database.
            if skip_more_than_one and len(out) > 1:
                break
            ea = hit + 1
        return out

    @classmethod
    def count_matches(
        cls,
        ida_signature: str,
        buf: typing.Optional["InMemoryBuffer"] = None,
    ) -> int:
        """Return the number of matches for the given IDA-format signature.

        Enumerates every match; callers that only need uniqueness should use
        is_unique (which bails at the second match).
        """
        return len(cls.find_all(ida_signature, buf=buf))

    @classmethod
    def is_unique(
        cls,
        ida_signature: str,
        buf: typing.Optional["InMemoryBuffer"] = None,
    ) -> bool:
        """Return True iff the signature matches exactly one location.

        Bails at the second match. Enumerating all matches of a short, common
        signature is catastrophic on a large binary, and uniqueness only
        depends on whether the count is 0, 1, or 2+.
        """
        matches = cls.find_all(ida_signature, buf=buf, skip_more_than_one=True)
        return len(matches) == 1
