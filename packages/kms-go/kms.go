package kms

import "github.com/theodorepender/kms/packages/kms-go/internal/ffi"

type Felt = ffi.Felt
type ProjectivePoint = ffi.ProjectivePoint
type AffinePoint = ffi.AffinePoint
type TongoKeyPair = ffi.TongoKeyPair
type NostrKeyPair = ffi.NostrKeyPair
type Error = ffi.Error

func GetVersion() (string, error) {
	return ffi.GetVersion()
}

func CoinTypes() (tongo, starknet, tongoView, nostr uint32) {
	return ffi.CoinTypes()
}

func ErrorName(code int32) string {
	return ffi.ErrorName(code)
}

func ErrorMessage(code int32) string {
	return ffi.ErrorMessage(code)
}

func FeltFromHex(hex string) (Felt, error) {
	return ffi.FeltFromHex(hex)
}

func FeltToHex(value Felt) (string, error) {
	return ffi.FeltToHex(value)
}

func FeltFromBytesBe(bytes []byte) (Felt, error) {
	return ffi.FeltFromBytesBe(bytes)
}

func FeltToBytesBe(value Felt) ([]byte, error) {
	return ffi.FeltToBytesBe(value)
}

func ProjectiveFromAffine(affine AffinePoint) (ProjectivePoint, error) {
	return ffi.ProjectiveFromAffine(affine)
}

func ProjectiveToAffine(point ProjectivePoint) (AffinePoint, error) {
	return ffi.ProjectiveToAffine(point)
}

func PedersenHash(left, right Felt) (Felt, error) {
	return ffi.PedersenHash(left, right)
}

func PoseidonHashMany(values []Felt) (Felt, error) {
	return ffi.PoseidonHashMany(values)
}

func GenerateMnemonic(wordCount uint32) (string, error) {
	return ffi.GenerateMnemonic(wordCount)
}

func GenerateMnemonicFromEntropy(entropy []byte) (string, error) {
	return ffi.GenerateMnemonicFromEntropy(entropy)
}

func ValidateMnemonic(phrase string) error {
	return ffi.ValidateMnemonic(phrase)
}

func MnemonicToSeed(phrase, passphrase string) ([]byte, error) {
	return ffi.MnemonicToSeed(phrase, passphrase)
}

func DerivePrivateKey(mnemonic string, index, accountIndex, coinType uint32, passphrase string) (Felt, error) {
	return ffi.DerivePrivateKey(mnemonic, index, accountIndex, coinType, passphrase)
}

func DeriveKeypair(mnemonic string, index, accountIndex, coinType uint32, passphrase string) (TongoKeyPair, error) {
	return ffi.DeriveKeypair(mnemonic, index, accountIndex, coinType, passphrase)
}

func DeriveViewPrivateKey(mnemonic string, index, accountIndex uint32, passphrase string) (Felt, error) {
	return ffi.DeriveViewPrivateKey(mnemonic, index, accountIndex, passphrase)
}

func DeriveViewKeypair(mnemonic string, index, accountIndex uint32, passphrase string) (TongoKeyPair, error) {
	return ffi.DeriveViewKeypair(mnemonic, index, accountIndex, passphrase)
}

func DeriveNostrPrivateKey(mnemonic string, index, accountIndex uint32, passphrase string) ([32]byte, error) {
	return ffi.DeriveNostrPrivateKey(mnemonic, index, accountIndex, passphrase)
}

func DeriveNostrKeypair(mnemonic string, index, accountIndex uint32, passphrase string) (NostrKeyPair, error) {
	return ffi.DeriveNostrKeypair(mnemonic, index, accountIndex, passphrase)
}

func CalculateContractAddress(salt, classHash Felt, constructorCalldata []Felt, deployerAddress Felt) (Felt, error) {
	return ffi.CalculateContractAddress(salt, classHash, constructorCalldata, deployerAddress)
}

func DeriveOzAccountAddress(publicKeyX, classHash Felt, salt *Felt) (Felt, error) {
	return ffi.DeriveOzAccountAddress(publicKeyX, classHash, salt)
}
