package owchcca

import (
	cryptoRand "crypto/rand"

	"OW-ChCCA-KEM/internal"
)

type (
	SharedParam = internal.SharedParam
	PublicKey   = internal.PublicKey
	PrivateKey  = internal.PrivateKey
	Mat         = internal.Mat
)

// A Scheme represents a specific instance of a KEM.
type Scheme interface {
	// Name of the scheme
	Name() string

	// GenerateKeyPair creates a new key pair.
	GenerateKeyPair() (*PublicKey, *PrivateKey, *SharedParam, error)

	// GenerateNewKeyPair creates a new key pair from a shared key.
	GenerateNewKeyPair(ss SharedParam) (*PublicKey, *PrivateKey, error)

	// Encapsulate generates a shared key ss for the public key and
	// encapsulates it into a ciphertext ct.
	Encapsulate(pk PublicKey) (ct, ss []byte, err error)

	// Decapsulate Returns the shared key encapsulated in ciphertext ct for the
	// private key sk.
	Decapsulate(sk PrivateKey, ct []byte) ([]byte, error)

	// MarshalBinaryPublicKey marshals a PublicKey into a binary form.
	MarshalBinaryPublicKey(pk PublicKey) ([]byte, error)

	// MarshalBinaryPrivateKey marshals a PrivateKey into a binary form.
	MarshalBinaryPrivateKey(sk PrivateKey) ([]byte, error)

	// UnmarshalBinaryPublicKey Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// UnmarshalBinaryPrivateKey Unmarshals a PrivateKey from the provided buffer.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)

	// CiphertextSize Size of encapsulated keys.
	CiphertextSize() int

	// SharedKeySize Size of established shared keys.
	SharedKeySize() int

	// PrivateKeySize Size of packed private keys.
	PrivateKeySize() int

	// PublicKeySize Size of packed public keys.
	PublicKeySize() int
}

// Name of the scheme
func Name() string {
	return "OW-ChCCA-KEM"
}

// Setup generates a shared parameter for the scheme.
func Setup() *SharedParam {
	return internal.Setup(cryptoRand.Reader)
}

// GenerateKeyPair generates a public/private key pair using entropy from rand.
// Paper uses the seed from Setup with par := random(Z_q, n x m)
func GenerateKeyPair() (*PublicKey, *PrivateKey, *SharedParam, error) {
	rand := cryptoRand.Reader
	pk, sk, ss, err := internal.InitKey(rand)
	if err != nil {
		return nil, nil, nil, err
	}
	return pk, sk, ss, nil
}

// GenerateNewKeyPair generates a public/private key pair using entropy from rand.
func GenerateNewKeyPair(ss SharedParam) (*PublicKey, *PrivateKey, error) {
	rand := cryptoRand.Reader
	pk, sk, err := internal.NewKey(rand, &ss)
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

// MarshalBinaryPublicKey marshals a PublicKey into a binary form.
func MarshalBinaryPublicKey(pk PublicKey) ([]byte, error) {
	return pk.MarshalBinary()
}

// MarshalBinaryPrivateKey marshals a PrivateKey into a binary form.
func MarshalBinaryPrivateKey(sk PrivateKey) ([]byte, error) {
	return sk.MarshalBinary()
}

// UnmarshalBinaryPublicKey Unmarshals a PublicKey from the provided buffer.
func UnmarshalBinaryPublicKey(buf []byte, sp SharedParam) (PublicKey, error) {
	return UnmarshalBinaryPublicKey(buf, sp)
}

// UnmarshalBinaryPrivateKey Unmarshals a PrivateKey from the provided buffer.
func UnmarshalBinaryPrivateKey(buf []byte, pk PublicKey, sp SharedParam) (PrivateKey, error) {
	return UnmarshalBinaryPrivateKey(buf, pk, sp)
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
