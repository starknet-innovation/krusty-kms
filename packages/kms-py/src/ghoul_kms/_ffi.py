from __future__ import annotations

import ctypes
import os
import platform
from ctypes import POINTER, Structure, c_char, c_char_p, c_int32, c_size_t, c_uint8, c_uint32
from pathlib import Path


class KmsFelt(Structure):
    _fields_ = [("bytes", c_uint8 * 32)]


class KmsProjectivePoint(Structure):
    _fields_ = [("x", KmsFelt), ("y", KmsFelt), ("z", KmsFelt)]


class KmsAffinePoint(Structure):
    _fields_ = [("x", KmsFelt), ("y", KmsFelt)]


class KmsTongoKeyPair(Structure):
    _fields_ = [("private_key", KmsFelt), ("public_key", KmsProjectivePoint)]


class KmsNostrKeyPair(Structure):
    _fields_ = [("private_key", c_uint8 * 32), ("public_key_xonly", c_uint8 * 32)]


class KmsLib:
    def __init__(self) -> None:
        self.lib = self._load_lib()
        self._bind()

    def _load_lib(self) -> ctypes.CDLL:
        env_path = os.environ.get("KMS_LIB_PATH") or os.environ.get("VOLTAIRE_LIB_PATH")
        if env_path and Path(env_path).exists():
            return ctypes.CDLL(env_path)

        system = platform.system()
        if system == "Darwin":
            name = "libkms.dylib"
        elif system == "Windows":
            name = "kms.dll"
        else:
            name = "libkms.so"

        root = Path(__file__).resolve().parents[4]
        candidate = root / "zig" / "zig-out" / "lib" / name
        if candidate.exists():
            return ctypes.CDLL(str(candidate))

        raise OSError("could not locate libkms; build zig library or set KMS_LIB_PATH")

    def _bind(self) -> None:
        self.lib.kms_get_abi_version.argtypes = [POINTER(c_uint32), POINTER(c_uint32)]
        self.lib.kms_get_abi_version.restype = c_int32

        self.lib.kms_get_version_string.argtypes = [POINTER(c_char), c_size_t, POINTER(c_size_t)]
        self.lib.kms_get_version_string.restype = c_int32

        self.lib.kms_felt_from_hex.argtypes = [c_char_p, POINTER(KmsFelt)]
        self.lib.kms_felt_from_hex.restype = c_int32
        self.lib.kms_felt_to_hex.argtypes = [POINTER(KmsFelt), POINTER(c_char), c_size_t, POINTER(c_size_t)]
        self.lib.kms_felt_to_hex.restype = c_int32
        self.lib.kms_felt_from_bytes_be.argtypes = [POINTER(c_uint8), c_size_t, POINTER(KmsFelt)]
        self.lib.kms_felt_from_bytes_be.restype = c_int32
        self.lib.kms_felt_to_bytes_be.argtypes = [POINTER(KmsFelt), POINTER(c_uint8), c_size_t, POINTER(c_size_t)]
        self.lib.kms_felt_to_bytes_be.restype = c_int32

        self.lib.kms_projective_from_affine.argtypes = [POINTER(KmsAffinePoint), POINTER(KmsProjectivePoint)]
        self.lib.kms_projective_from_affine.restype = c_int32
        self.lib.kms_projective_to_affine.argtypes = [POINTER(KmsProjectivePoint), POINTER(KmsAffinePoint)]
        self.lib.kms_projective_to_affine.restype = c_int32

        self.lib.kms_pedersen_hash.argtypes = [POINTER(KmsFelt), POINTER(KmsFelt), POINTER(KmsFelt)]
        self.lib.kms_pedersen_hash.restype = c_int32
        self.lib.kms_poseidon_hash_many.argtypes = [POINTER(KmsFelt), c_size_t, POINTER(KmsFelt)]
        self.lib.kms_poseidon_hash_many.restype = c_int32

        self.lib.kms_generate_mnemonic.argtypes = [c_uint32, POINTER(c_char), c_size_t, POINTER(c_size_t)]
        self.lib.kms_generate_mnemonic.restype = c_int32
        self.lib.kms_generate_mnemonic_from_entropy.argtypes = [
            POINTER(c_uint8),
            c_size_t,
            POINTER(c_char),
            c_size_t,
            POINTER(c_size_t),
        ]
        self.lib.kms_generate_mnemonic_from_entropy.restype = c_int32
        self.lib.kms_validate_mnemonic.argtypes = [c_char_p]
        self.lib.kms_validate_mnemonic.restype = c_int32
        self.lib.kms_mnemonic_to_seed.argtypes = [
            c_char_p,
            c_char_p,
            POINTER(c_uint8),
            c_size_t,
            POINTER(c_size_t),
        ]
        self.lib.kms_mnemonic_to_seed.restype = c_int32

        self.lib.kms_derive_private_key_with_coin_type.argtypes = [
            c_char_p,
            c_uint32,
            c_uint32,
            c_uint32,
            c_char_p,
            POINTER(KmsFelt),
        ]
        self.lib.kms_derive_private_key_with_coin_type.restype = c_int32

        self.lib.kms_derive_keypair_with_coin_type.argtypes = [
            c_char_p,
            c_uint32,
            c_uint32,
            c_uint32,
            c_char_p,
            POINTER(KmsTongoKeyPair),
        ]
        self.lib.kms_derive_keypair_with_coin_type.restype = c_int32

        self.lib.kms_derive_view_private_key.argtypes = [
            c_char_p,
            c_uint32,
            c_uint32,
            c_char_p,
            POINTER(KmsFelt),
        ]
        self.lib.kms_derive_view_private_key.restype = c_int32

        self.lib.kms_derive_view_keypair.argtypes = [
            c_char_p,
            c_uint32,
            c_uint32,
            c_char_p,
            POINTER(KmsTongoKeyPair),
        ]
        self.lib.kms_derive_view_keypair.restype = c_int32

        self.lib.kms_derive_nostr_private_key.argtypes = [
            c_char_p,
            c_uint32,
            c_uint32,
            c_char_p,
            POINTER(c_uint8),
        ]
        self.lib.kms_derive_nostr_private_key.restype = c_int32

        self.lib.kms_derive_nostr_keypair.argtypes = [
            c_char_p,
            c_uint32,
            c_uint32,
            c_char_p,
            POINTER(KmsNostrKeyPair),
        ]
        self.lib.kms_derive_nostr_keypair.restype = c_int32

        self.lib.kms_calculate_contract_address.argtypes = [
            POINTER(KmsFelt),
            POINTER(KmsFelt),
            POINTER(KmsFelt),
            c_size_t,
            POINTER(KmsFelt),
            POINTER(KmsFelt),
        ]
        self.lib.kms_calculate_contract_address.restype = c_int32

        self.lib.kms_derive_oz_account_address.argtypes = [
            POINTER(KmsFelt),
            POINTER(KmsFelt),
            POINTER(KmsFelt),
            POINTER(KmsFelt),
        ]
        self.lib.kms_derive_oz_account_address.restype = c_int32

        self.lib.kms_get_coin_type_tongo.restype = c_uint32
        self.lib.kms_get_coin_type_starknet.restype = c_uint32
        self.lib.kms_get_coin_type_tongo_view.restype = c_uint32
        self.lib.kms_get_coin_type_nostr.restype = c_uint32

        self.lib.kms_error_name.argtypes = [c_int32]
        self.lib.kms_error_name.restype = c_char_p
        self.lib.kms_error_message.argtypes = [c_int32]
        self.lib.kms_error_message.restype = c_char_p


kms = KmsLib()
