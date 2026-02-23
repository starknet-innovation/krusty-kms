from __future__ import annotations

import ctypes
from dataclasses import dataclass

from ._ffi import (
    KmsAffinePoint,
    KmsFelt,
    KmsNostrKeyPair,
    KmsProjectivePoint,
    KmsTongoKeyPair,
    kms,
)


class KmsError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"kms error {code}: {message}")
        self.code = code
        self.message = message


def _check(code: int) -> None:
    if code == 0:
        return
    msg = kms.lib.kms_error_message(code)
    raise KmsError(code, msg.decode("utf-8") if msg else "unknown error")


def _dynamic_string(callable_fn) -> str:
    written = ctypes.c_size_t(0)
    _check(callable_fn(None, 0, ctypes.byref(written)))
    buf = (ctypes.c_char * (written.value + 1))()
    _check(callable_fn(buf, len(buf), ctypes.byref(written)))
    return ctypes.string_at(buf, written.value).decode("utf-8")


@dataclass(frozen=True)
class Felt:
    bytes: bytes

    def __post_init__(self) -> None:
        if len(self.bytes) != 32:
            raise ValueError("felt must be 32 bytes")

    @staticmethod
    def from_hex(hex_value: str) -> "Felt":
        out = KmsFelt()
        _check(kms.lib.kms_felt_from_hex(hex_value.encode("utf-8"), ctypes.byref(out)))
        return _felt_from_c(out)

    def to_hex(self) -> str:
        c_felt = _felt_to_c(self)
        return _dynamic_string(
            lambda out, out_len, written: kms.lib.kms_felt_to_hex(
                ctypes.byref(c_felt), out, out_len, written
            )
        )


@dataclass(frozen=True)
class AffinePoint:
    x: Felt
    y: Felt


@dataclass(frozen=True)
class ProjectivePoint:
    x: Felt
    y: Felt
    z: Felt


@dataclass(frozen=True)
class TongoKeyPair:
    private_key: Felt
    public_key: ProjectivePoint


@dataclass(frozen=True)
class NostrKeyPair:
    private_key: bytes
    public_key_xonly: bytes


def _felt_from_c(value: KmsFelt) -> Felt:
    return Felt(bytes=bytes(value.bytes))


def _felt_to_c(value: Felt) -> KmsFelt:
    out = KmsFelt()
    for i, byte in enumerate(value.bytes):
        out.bytes[i] = byte
    return out


def _affine_to_c(point: AffinePoint) -> KmsAffinePoint:
    return KmsAffinePoint(x=_felt_to_c(point.x), y=_felt_to_c(point.y))


def _affine_from_c(point: KmsAffinePoint) -> AffinePoint:
    return AffinePoint(x=_felt_from_c(point.x), y=_felt_from_c(point.y))


def _projective_to_c(point: ProjectivePoint) -> KmsProjectivePoint:
    return KmsProjectivePoint(
        x=_felt_to_c(point.x),
        y=_felt_to_c(point.y),
        z=_felt_to_c(point.z),
    )


def _projective_from_c(point: KmsProjectivePoint) -> ProjectivePoint:
    return ProjectivePoint(
        x=_felt_from_c(point.x),
        y=_felt_from_c(point.y),
        z=_felt_from_c(point.z),
    )


def get_abi_version() -> tuple[int, int]:
    major = ctypes.c_uint32(0)
    minor = ctypes.c_uint32(0)
    _check(kms.lib.kms_get_abi_version(ctypes.byref(major), ctypes.byref(minor)))
    return int(major.value), int(minor.value)


def get_version_string() -> str:
    return _dynamic_string(kms.lib.kms_get_version_string)


def error_name(code: int) -> str:
    name = kms.lib.kms_error_name(code)
    return name.decode("utf-8") if name else "KMS_ERR_INTERNAL"


def error_message(code: int) -> str:
    message = kms.lib.kms_error_message(code)
    return message.decode("utf-8") if message else "unknown error"


def coin_types() -> dict[str, int]:
    return {
        "tongo": int(kms.lib.kms_get_coin_type_tongo()),
        "starknet": int(kms.lib.kms_get_coin_type_starknet()),
        "tongo_view": int(kms.lib.kms_get_coin_type_tongo_view()),
        "nostr": int(kms.lib.kms_get_coin_type_nostr()),
    }


def felt_from_bytes_be(data: bytes) -> Felt:
    out = KmsFelt()
    buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    _check(kms.lib.kms_felt_from_bytes_be(buf, len(data), ctypes.byref(out)))
    return _felt_from_c(out)


def felt_to_bytes_be(value: Felt) -> bytes:
    out = (ctypes.c_uint8 * 32)()
    written = ctypes.c_size_t(0)
    c_felt = _felt_to_c(value)
    _check(
        kms.lib.kms_felt_to_bytes_be(
            ctypes.byref(c_felt),
            out,
            len(out),
            ctypes.byref(written),
        )
    )
    return bytes(out[: written.value])


def projective_from_affine(value: AffinePoint) -> ProjectivePoint:
    out = KmsProjectivePoint()
    c_affine = _affine_to_c(value)
    _check(kms.lib.kms_projective_from_affine(ctypes.byref(c_affine), ctypes.byref(out)))
    return _projective_from_c(out)


def projective_to_affine(value: ProjectivePoint) -> AffinePoint:
    out = KmsAffinePoint()
    c_point = _projective_to_c(value)
    _check(kms.lib.kms_projective_to_affine(ctypes.byref(c_point), ctypes.byref(out)))
    return _affine_from_c(out)


def pedersen_hash(left: Felt, right: Felt) -> Felt:
    out = KmsFelt()
    c_left = _felt_to_c(left)
    c_right = _felt_to_c(right)
    _check(kms.lib.kms_pedersen_hash(ctypes.byref(c_left), ctypes.byref(c_right), ctypes.byref(out)))
    return _felt_from_c(out)


def poseidon_hash_many(values: list[Felt]) -> Felt:
    out = KmsFelt()
    if values:
        c_values = (KmsFelt * len(values))(*[_felt_to_c(value) for value in values])
        ptr = ctypes.cast(c_values, ctypes.POINTER(KmsFelt))
    else:
        c_values = None
        ptr = None
    _check(kms.lib.kms_poseidon_hash_many(ptr, len(values), ctypes.byref(out)))
    _ = c_values
    return _felt_from_c(out)


def generate_mnemonic(word_count: int) -> str:
    return _dynamic_string(
        lambda out, out_len, written: kms.lib.kms_generate_mnemonic(
            word_count, out, out_len, written
        )
    )


def generate_mnemonic_from_entropy(entropy: bytes) -> str:
    if entropy:
        entropy_buf = (ctypes.c_uint8 * len(entropy)).from_buffer_copy(entropy)
        ptr = entropy_buf
    else:
        entropy_buf = None
        ptr = None
    result = _dynamic_string(
        lambda out, out_len, written: kms.lib.kms_generate_mnemonic_from_entropy(
            ptr,
            len(entropy),
            out,
            out_len,
            written,
        )
    )
    _ = entropy_buf
    return result


def validate_mnemonic(phrase: str) -> None:
    _check(kms.lib.kms_validate_mnemonic(phrase.encode("utf-8")))


def mnemonic_to_seed(phrase: str, passphrase: str = "") -> bytes:
    buf = (ctypes.c_uint8 * 64)()
    written = ctypes.c_size_t(0)
    _check(
        kms.lib.kms_mnemonic_to_seed(
            phrase.encode("utf-8"),
            passphrase.encode("utf-8"),
            buf,
            len(buf),
            ctypes.byref(written),
        )
    )
    return bytes(buf[: written.value])


def derive_private_key(
    mnemonic: str,
    index: int,
    account_index: int,
    coin_type: int,
    passphrase: str = "",
) -> Felt:
    out = KmsFelt()
    _check(
        kms.lib.kms_derive_private_key_with_coin_type(
            mnemonic.encode("utf-8"),
            index,
            account_index,
            coin_type,
            passphrase.encode("utf-8"),
            ctypes.byref(out),
        )
    )
    return _felt_from_c(out)


def derive_keypair(
    mnemonic: str,
    index: int,
    account_index: int,
    coin_type: int,
    passphrase: str = "",
) -> TongoKeyPair:
    out = KmsTongoKeyPair()
    _check(
        kms.lib.kms_derive_keypair_with_coin_type(
            mnemonic.encode("utf-8"),
            index,
            account_index,
            coin_type,
            passphrase.encode("utf-8"),
            ctypes.byref(out),
        )
    )
    return TongoKeyPair(
        private_key=_felt_from_c(out.private_key),
        public_key=_projective_from_c(out.public_key),
    )


def derive_view_private_key(
    mnemonic: str,
    index: int,
    account_index: int,
    passphrase: str = "",
) -> Felt:
    out = KmsFelt()
    _check(
        kms.lib.kms_derive_view_private_key(
            mnemonic.encode("utf-8"),
            index,
            account_index,
            passphrase.encode("utf-8"),
            ctypes.byref(out),
        )
    )
    return _felt_from_c(out)


def derive_view_keypair(
    mnemonic: str,
    index: int,
    account_index: int,
    passphrase: str = "",
) -> TongoKeyPair:
    out = KmsTongoKeyPair()
    _check(
        kms.lib.kms_derive_view_keypair(
            mnemonic.encode("utf-8"),
            index,
            account_index,
            passphrase.encode("utf-8"),
            ctypes.byref(out),
        )
    )
    return TongoKeyPair(
        private_key=_felt_from_c(out.private_key),
        public_key=_projective_from_c(out.public_key),
    )


def derive_nostr_private_key(
    mnemonic: str,
    index: int,
    account_index: int,
    passphrase: str = "",
) -> bytes:
    out = (ctypes.c_uint8 * 32)()
    _check(
        kms.lib.kms_derive_nostr_private_key(
            mnemonic.encode("utf-8"),
            index,
            account_index,
            passphrase.encode("utf-8"),
            out,
        )
    )
    return bytes(out)


def derive_nostr_keypair(
    mnemonic: str,
    index: int,
    account_index: int,
    passphrase: str = "",
) -> NostrKeyPair:
    out = KmsNostrKeyPair()
    _check(
        kms.lib.kms_derive_nostr_keypair(
            mnemonic.encode("utf-8"),
            index,
            account_index,
            passphrase.encode("utf-8"),
            ctypes.byref(out),
        )
    )
    return NostrKeyPair(
        private_key=bytes(out.private_key),
        public_key_xonly=bytes(out.public_key_xonly),
    )


def calculate_contract_address(
    salt: Felt,
    class_hash: Felt,
    constructor_calldata: list[Felt],
    deployer: Felt,
) -> Felt:
    out = KmsFelt()
    c_salt = _felt_to_c(salt)
    c_class_hash = _felt_to_c(class_hash)
    c_deployer = _felt_to_c(deployer)

    if constructor_calldata:
        c_calldata = (KmsFelt * len(constructor_calldata))(
            *[_felt_to_c(value) for value in constructor_calldata]
        )
        ptr = ctypes.cast(c_calldata, ctypes.POINTER(KmsFelt))
    else:
        c_calldata = None
        ptr = None

    _check(
        kms.lib.kms_calculate_contract_address(
            ctypes.byref(c_salt),
            ctypes.byref(c_class_hash),
            ptr,
            len(constructor_calldata),
            ctypes.byref(c_deployer),
            ctypes.byref(out),
        )
    )
    _ = c_calldata
    return _felt_from_c(out)


def derive_oz_account_address(public_key_x: Felt, class_hash: Felt, salt: Felt | None = None) -> Felt:
    out = KmsFelt()
    c_public_key_x = _felt_to_c(public_key_x)
    c_class_hash = _felt_to_c(class_hash)

    c_salt = _felt_to_c(salt) if salt is not None else None
    salt_ptr = ctypes.byref(c_salt) if c_salt is not None else None

    _check(
        kms.lib.kms_derive_oz_account_address(
            ctypes.byref(c_public_key_x),
            ctypes.byref(c_class_hash),
            salt_ptr,
            ctypes.byref(out),
        )
    )
    return _felt_from_c(out)


__all__ = [
    "AffinePoint",
    "Felt",
    "KmsError",
    "NostrKeyPair",
    "ProjectivePoint",
    "TongoKeyPair",
    "calculate_contract_address",
    "coin_types",
    "derive_keypair",
    "derive_nostr_keypair",
    "derive_nostr_private_key",
    "derive_oz_account_address",
    "derive_private_key",
    "derive_view_keypair",
    "derive_view_private_key",
    "error_message",
    "error_name",
    "felt_from_bytes_be",
    "generate_mnemonic",
    "generate_mnemonic_from_entropy",
    "get_abi_version",
    "get_version_string",
    "mnemonic_to_seed",
    "pedersen_hash",
    "poseidon_hash_many",
    "projective_from_affine",
    "projective_to_affine",
    "validate_mnemonic",
]
