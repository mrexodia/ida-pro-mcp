"""
Vendored sigmaker core — signature creation and scanning engine.

Original: sigmaker.py - IDA Python Signature Maker
https://github.com/mahmoudimus/ida-sigmaker
by @mahmoudimus (Mahmoud Abdelkader)

This is a stripped-down, self-contained copy of the sigmaker library
with GUI/plugin code removed.  Only the engine classes are kept so that
api_sigmaker.py can use them without an external dependency.

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
__version__ = "1.6.0"


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
        return cls(frozenset(cls.BaseKind) | frozenset(cls.X86Kind))

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
    signature: Signature
    address: Match | None = None

    def __lt__(self, other) -> bool:
        if not isinstance(other, GeneratedSignature):
            return NotImplemented
        return len(self.signature) < len(other.signature)


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

            self.processor.append_instruction_to_sig(
                sig, cur_ea, ins, cfg.wildcard_operands, cfg.wildcard_optimized
            )
            bytes_since_last_check += ins_len

            if SignatureSearcher.is_unique(f"{sig:ida}"):
                sig.trim_signature()
                return sig

        raise Unexpected("Signature not unique (reached end of analysis)")


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

    def __post_init__(self):
        self._instruction_processor = InstructionProcessor(self._operand_processor)
        self._unique_generator = UniqueSignatureGenerator(self._instruction_processor)
        self._range_generator = RangeSignatureGenerator(self._instruction_processor)

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
        ida_signature: str, skip_more_than_one: bool = False
    ) -> list[Match]:
        simd_signature, _ = SigText.normalize(ida_signature)
        buf = InMemoryBuffer.load(mode=InMemoryBuffer.LoadMode.SEGMENTS)
        data_mv = buf.data()

        sig = _SimdSignature(simd_signature)
        results: list[Match] = []
        base = idaapi.inf_get_min_ea()
        if (k := sig.size_bytes) == 0:
            return [Match(base)]

        n = len(data_mv)
        off = 0
        while off <= n - k:
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
    def find_all(ida_signature: str) -> list[Match]:
        if SIMD_SPEEDUP_AVAILABLE:
            return SignatureSearcher._find_all_simd(ida_signature)
        binary = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(binary, idaapi.inf_get_min_ea(), ida_signature, 16)
        out: list[Match] = []
        ea = idaapi.inf_get_min_ea()
        _bin_search = getattr(idaapi, "bin_search", None) or getattr(
            idaapi, "bin_search3"
        )
        while True:
            hit, _ = _bin_search(
                ea,
                idaapi.inf_get_max_ea(),
                binary,
                idaapi.BIN_SEARCH_NOCASE | idaapi.BIN_SEARCH_FORWARD,
            )
            if hit == idaapi.BADADDR:
                break
            out.append(Match(hit))
            ea = hit + 1
        return out

    @classmethod
    def is_unique(cls, ida_signature: str) -> bool:
        return len(cls.find_all(ida_signature)) == 1
