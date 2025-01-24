package owchcca

import (
	"OW-ChCCA-KEM/internal"
)

type (
	SharedParam = internal.SharedParam
	PublicKey   = internal.PublicKey
	PrivateKey  = internal.PrivateKey
	Mat         = internal.Mat
)

var Random = internal.RandReader

// Name of the scheme
func Name() string {
	return "OW-ChCCA-KEM"
}

// Setup generates a shared parameter for the scheme.
func Setup() *SharedParam {
	return internal.Setup(Random)
}

// GenerateKeyPair generates a public/private key pair using entropy from rand.
// Paper uses the seed from Setup with par := random(Z_q, n x m)
func GenerateKeyPair() (*PublicKey, *PrivateKey, *SharedParam, error) {
	pk, sk, ss, err := internal.InitKey(Random)
	if err != nil {
		return nil, nil, nil, err
	}
	return pk, sk, ss, nil
}

// GenerateNewKeyPair generates a public/private key pair using entropy from rand.
func GenerateNewKeyPair(ss SharedParam) (*PublicKey, *PrivateKey, error) {
	pk, sk, err := internal.NewKey(Random, &ss)
	if err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

// Encapsulate generates a shared key ss for the public key and
// encapsulates it into a ciphertext ct.
func Encapsulate(pk PublicKey) ([]byte, []byte, error) {
	return pk.EncapsulateTo()
}

// Decapsulate Returns the shared key encapsulated in ciphertext ct for the
// private key sk.
func Decapsulate(sk PrivateKey, ct []byte) ([]byte, error) {
	return sk.DecapsulateTo(ct)
}

// MarshalSharedParam marshals a SharedParam into a binary form.
func MarshalSharedParam(sp SharedParam) ([]byte, error) {
	return sp.MarshalBinary()
}

// MarshalBinaryPublicKey marshals a PublicKey into a binary form.
func MarshalBinaryPublicKey(pk PublicKey) ([]byte, error) {
	return pk.MarshalBinary()
}

// MarshalBinaryPrivateKey marshals a PrivateKey into a binary form.
func MarshalBinaryPrivateKey(sk PrivateKey) ([]byte, error) {
	return sk.MarshalBinary()
}

// UnmarshalSharedParam Unmarshals a SharedParam from the provided buffer.
func UnmarshalSharedParam(buf []byte) (SharedParam, error) {
	var sp SharedParam
	err := sp.UnmarshalBinary(buf)
	return sp, err
}

// UnmarshalBinaryPublicKey Unmarshals a PublicKey from the provided buffer.
func UnmarshalBinaryPublicKey(buf []byte, sp SharedParam) (PublicKey, error) {
	var pk PublicKey
	err := pk.UnmarshalBinary(buf, &sp)
	return pk, err
}

// UnmarshalBinaryPrivateKey Unmarshals a PrivateKey from the provided buffer.
func UnmarshalBinaryPrivateKey(buf []byte, pk PublicKey, sp SharedParam) (PrivateKey, error) {
	var sk PrivateKey
	err := sk.UnmarshalBinary(buf, &sp, &pk)
	return sk, err
}

// CiphertextSize Size of encapsulated keys.
func CiphertextSize() int {
	return internal.CiphertextSize
}

// SharedKeySize Size of established shared keys.
func SharedKeySize() int {
	return internal.SharedKeySize
}

// PrivateKeySize Size of packed private keys.
func PrivateKeySize() int {
	return internal.PrivateKeySize
}

// PublicKeySize Size of packed public keys.
func PublicKeySize() int {
	return internal.PublicKeySize
}
