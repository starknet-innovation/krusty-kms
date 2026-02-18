package ffi

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -L${SRCDIR}/../../../../zig/zig-out/lib -Wl,-rpath,${SRCDIR}/../../../../zig/zig-out/lib -lkms

#include "kms.h"
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

type Felt [32]byte

type ProjectivePoint struct {
	X Felt
	Y Felt
	Z Felt
}

type AffinePoint struct {
	X Felt
	Y Felt
}

type TongoKeyPair struct {
	PrivateKey Felt
	PublicKey  ProjectivePoint
}

type NostrKeyPair struct {
	PrivateKey     [32]byte
	PublicKeyXOnly [32]byte
}

type Error struct {
	Code int32
	Msg  string
}

func (e Error) Error() string { return e.Msg }

func toError(code C.int32_t) error {
	if int32(code) == 0 {
		return nil
	}
	msg := C.GoString(C.kms_error_message(code))
	return Error{Code: int32(code), Msg: msg}
}

func cFelt(in Felt) C.KmsFelt {
	var out C.KmsFelt
	for i := 0; i < len(in); i++ {
		out.bytes[i] = C.uint8_t(in[i])
	}
	return out
}

func fromCFelt(in C.KmsFelt) Felt {
	var out Felt
	for i := 0; i < len(out); i++ {
		out[i] = byte(in.bytes[i])
	}
	return out
}

func cAffine(in AffinePoint) C.KmsAffinePoint {
	return C.KmsAffinePoint{
		x: cFelt(in.X),
		y: cFelt(in.Y),
	}
}

func fromCAffine(in C.KmsAffinePoint) AffinePoint {
	return AffinePoint{
		X: fromCFelt(in.x),
		Y: fromCFelt(in.y),
	}
}

func fromCProjective(in C.KmsProjectivePoint) ProjectivePoint {
	return ProjectivePoint{
		X: fromCFelt(in.x),
		Y: fromCFelt(in.y),
		Z: fromCFelt(in.z),
	}
}

func fromCTongoKeyPair(in C.KmsTongoKeyPair) TongoKeyPair {
	return TongoKeyPair{
		PrivateKey: fromCFelt(in.private_key),
		PublicKey:  fromCProjective(in.public_key),
	}
}

func fromCNostrKeyPair(in C.KmsNostrKeyPair) NostrKeyPair {
	var priv [32]byte
	var pub [32]byte
	for i := 0; i < 32; i++ {
		priv[i] = byte(in.private_key[i])
		pub[i] = byte(in.public_key_xonly[i])
	}
	return NostrKeyPair{
		PrivateKey:     priv,
		PublicKeyXOnly: pub,
	}
}

func getDynamicString(call func(*C.char, C.size_t, *C.size_t) C.int32_t) (string, error) {
	written := C.size_t(0)
	rc := call(nil, 0, &written)
	if err := toError(rc); err != nil {
		return "", err
	}

	buf := make([]byte, int(written)+1)
	rc = call((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &written)
	if err := toError(rc); err != nil {
		return "", err
	}
	return C.GoStringN((*C.char)(unsafe.Pointer(&buf[0])), C.int(written)), nil
}

func GetVersion() (string, error) {
	return getDynamicString(func(out *C.char, outLen C.size_t, written *C.size_t) C.int32_t {
		return C.kms_get_version_string(out, outLen, written)
	})
}

func CoinTypes() (tongo, starknet, tongoView, nostr uint32) {
	return uint32(C.kms_get_coin_type_tongo()),
		uint32(C.kms_get_coin_type_starknet()),
		uint32(C.kms_get_coin_type_tongo_view()),
		uint32(C.kms_get_coin_type_nostr())
}

func ErrorName(code int32) string {
	return C.GoString(C.kms_error_name(C.int32_t(code)))
}

func ErrorMessage(code int32) string {
	return C.GoString(C.kms_error_message(C.int32_t(code)))
}

func FeltFromHex(hex string) (Felt, error) {
	ch := C.CString(hex)
	defer C.free(unsafe.Pointer(ch))

	var out C.KmsFelt
	rc := C.kms_felt_from_hex(ch, &out)
	if err := toError(rc); err != nil {
		return Felt{}, err
	}
	return fromCFelt(out), nil
}

func FeltToHex(value Felt) (string, error) {
	cvalue := cFelt(value)
	return getDynamicString(func(out *C.char, outLen C.size_t, written *C.size_t) C.int32_t {
		return C.kms_felt_to_hex(&cvalue, out, outLen, written)
	})
}

func FeltFromBytesBe(bytes []byte) (Felt, error) {
	var out C.KmsFelt
	var ptr *C.uint8_t
	if len(bytes) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&bytes[0]))
	}
	rc := C.kms_felt_from_bytes_be(ptr, C.size_t(len(bytes)), &out)
	if err := toError(rc); err != nil {
		return Felt{}, err
	}
	return fromCFelt(out), nil
}

func FeltToBytesBe(value Felt) ([]byte, error) {
	cvalue := cFelt(value)
	out := make([]byte, 32)
	written := C.size_t(0)
	rc := C.kms_felt_to_bytes_be(&cvalue, (*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(out)), &written)
	if err := toError(rc); err != nil {
		return nil, err
	}
	return out[:int(written)], nil
}

func ProjectiveFromAffine(affine AffinePoint) (ProjectivePoint, error) {
	caffine := cAffine(affine)
	var out C.KmsProjectivePoint
	rc := C.kms_projective_from_affine(&caffine, &out)
	if err := toError(rc); err != nil {
		return ProjectivePoint{}, err
	}
	return fromCProjective(out), nil
}

func ProjectiveToAffine(point ProjectivePoint) (AffinePoint, error) {
	cpoint := C.KmsProjectivePoint{
		x: cFelt(point.X),
		y: cFelt(point.Y),
		z: cFelt(point.Z),
	}
	var out C.KmsAffinePoint
	rc := C.kms_projective_to_affine(&cpoint, &out)
	if err := toError(rc); err != nil {
		return AffinePoint{}, err
	}
	return fromCAffine(out), nil
}

func PedersenHash(left, right Felt) (Felt, error) {
	cleft := cFelt(left)
	cright := cFelt(right)
	var out C.KmsFelt
	rc := C.kms_pedersen_hash(&cleft, &cright, &out)
	if err := toError(rc); err != nil {
		return Felt{}, err
	}
	return fromCFelt(out), nil
}

func PoseidonHashMany(values []Felt) (Felt, error) {
	cvalues := make([]C.KmsFelt, len(values))
	for i, v := range values {
		cvalues[i] = cFelt(v)
	}

	var ptr *C.KmsFelt
	if len(cvalues) > 0 {
		ptr = &cvalues[0]
	}
	var out C.KmsFelt
	rc := C.kms_poseidon_hash_many(ptr, C.size_t(len(cvalues)), &out)
	if err := toError(rc); err != nil {
		return Felt{}, err
	}
	return fromCFelt(out), nil
}

func GenerateMnemonic(wordCount uint32) (string, error) {
	return getDynamicString(func(out *C.char, outLen C.size_t, written *C.size_t) C.int32_t {
		return C.kms_generate_mnemonic(C.uint32_t(wordCount), out, outLen, written)
	})
}

func GenerateMnemonicFromEntropy(entropy []byte) (string, error) {
	var ptr *C.uint8_t
	if len(entropy) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&entropy[0]))
	}
	return getDynamicString(func(out *C.char, outLen C.size_t, written *C.size_t) C.int32_t {
		return C.kms_generate_mnemonic_from_entropy(ptr, C.size_t(len(entropy)), out, outLen, written)
	})
}

func ValidateMnemonic(phrase string) error {
	c := C.CString(phrase)
	defer C.free(unsafe.Pointer(c))
	return toError(C.kms_validate_mnemonic(c))
}

func MnemonicToSeed(phrase, passphrase string) ([]byte, error) {
	cp := C.CString(phrase)
	defer C.free(unsafe.Pointer(cp))
	cpp := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpp))

	out := make([]byte, 64)
	written := C.size_t(0)
	rc := C.kms_mnemonic_to_seed(
		cp,
		cpp,
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		C.size_t(len(out)),
		&written,
	)
	if err := toError(rc); err != nil {
		return nil, err
	}
	return out[:int(written)], nil
}

func DerivePrivateKey(mnemonic string, index, accountIndex, coinType uint32, passphrase string) (Felt, error) {
	cm := C.CString(mnemonic)
	defer C.free(unsafe.Pointer(cm))
	cp := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cp))

	var out C.KmsFelt
	rc := C.kms_derive_private_key_with_coin_type(
		cm,
		C.uint32_t(index),
		C.uint32_t(accountIndex),
		C.uint32_t(coinType),
		cp,
		&out,
	)
	if err := toError(rc); err != nil {
		return Felt{}, err
	}
	return fromCFelt(out), nil
}

func DeriveKeypair(mnemonic string, index, accountIndex, coinType uint32, passphrase string) (TongoKeyPair, error) {
	cm := C.CString(mnemonic)
	defer C.free(unsafe.Pointer(cm))
	cp := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cp))

	var out C.KmsTongoKeyPair
	rc := C.kms_derive_keypair_with_coin_type(
		cm,
		C.uint32_t(index),
		C.uint32_t(accountIndex),
		C.uint32_t(coinType),
		cp,
		&out,
	)
	if err := toError(rc); err != nil {
		return TongoKeyPair{}, err
	}
	return fromCTongoKeyPair(out), nil
}

func DeriveViewPrivateKey(mnemonic string, index, accountIndex uint32, passphrase string) (Felt, error) {
	cm := C.CString(mnemonic)
	defer C.free(unsafe.Pointer(cm))
	cp := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cp))

	var out C.KmsFelt
	rc := C.kms_derive_view_private_key(cm, C.uint32_t(index), C.uint32_t(accountIndex), cp, &out)
	if err := toError(rc); err != nil {
		return Felt{}, err
	}
	return fromCFelt(out), nil
}

func DeriveViewKeypair(mnemonic string, index, accountIndex uint32, passphrase string) (TongoKeyPair, error) {
	cm := C.CString(mnemonic)
	defer C.free(unsafe.Pointer(cm))
	cp := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cp))

	var out C.KmsTongoKeyPair
	rc := C.kms_derive_view_keypair(cm, C.uint32_t(index), C.uint32_t(accountIndex), cp, &out)
	if err := toError(rc); err != nil {
		return TongoKeyPair{}, err
	}
	return fromCTongoKeyPair(out), nil
}

func DeriveNostrPrivateKey(mnemonic string, index, accountIndex uint32, passphrase string) ([32]byte, error) {
	cm := C.CString(mnemonic)
	defer C.free(unsafe.Pointer(cm))
	cp := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cp))

	var out [32]byte
	rc := C.kms_derive_nostr_private_key(
		cm,
		C.uint32_t(index),
		C.uint32_t(accountIndex),
		cp,
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if err := toError(rc); err != nil {
		return [32]byte{}, err
	}
	return out, nil
}

func DeriveNostrKeypair(mnemonic string, index, accountIndex uint32, passphrase string) (NostrKeyPair, error) {
	cm := C.CString(mnemonic)
	defer C.free(unsafe.Pointer(cm))
	cp := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cp))

	var out C.KmsNostrKeyPair
	rc := C.kms_derive_nostr_keypair(cm, C.uint32_t(index), C.uint32_t(accountIndex), cp, &out)
	if err := toError(rc); err != nil {
		return NostrKeyPair{}, err
	}
	return fromCNostrKeyPair(out), nil
}

func CalculateContractAddress(salt, classHash Felt, constructorCalldata []Felt, deployerAddress Felt) (Felt, error) {
	csalt := cFelt(salt)
	cclassHash := cFelt(classHash)
	cdeployer := cFelt(deployerAddress)

	ccalldata := make([]C.KmsFelt, len(constructorCalldata))
	for i, v := range constructorCalldata {
		ccalldata[i] = cFelt(v)
	}

	var calldataPtr *C.KmsFelt
	if len(ccalldata) > 0 {
		calldataPtr = &ccalldata[0]
	}

	var out C.KmsFelt
	rc := C.kms_calculate_contract_address(
		&csalt,
		&cclassHash,
		calldataPtr,
		C.size_t(len(ccalldata)),
		&cdeployer,
		&out,
	)
	if err := toError(rc); err != nil {
		return Felt{}, err
	}
	return fromCFelt(out), nil
}

func DeriveOzAccountAddress(publicKeyX, classHash Felt, salt *Felt) (Felt, error) {
	cpublicKeyX := cFelt(publicKeyX)
	cclassHash := cFelt(classHash)

	var csalt C.KmsFelt
	var saltPtr *C.KmsFelt
	if salt != nil {
		csalt = cFelt(*salt)
		saltPtr = &csalt
	}

	var out C.KmsFelt
	rc := C.kms_derive_oz_account_address(&cpublicKeyX, &cclassHash, saltPtr, &out)
	if err := toError(rc); err != nil {
		return Felt{}, err
	}
	return fromCFelt(out), nil
}
