package owchcca

import (
	"io"

	"OW-ChCCA-KEM/internal"
)

const (
	// Size of seed for NewKeyFromSeed
	KeySeedSize = 32

	// Size of seed for EncapsulateTo.
	EncapsulationSeedSize = 32

	// Size of the established shared key.
	SharedKeySize = 32

	// Size of the encapsulated shared key.
	CiphertextSize = 32

	// Size of a packed public key.
	PublicKeySize = 32

	// Size of a packed private key.
	PrivateKeySize = 32
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
	GenerateKeyPair(par Mat) (*PublicKey, *PrivateKey, *SharedParam, error)

	// GenerateNewKeyPair creates a new key pair from a shared key.
	GenerateNewKeyPair(ss SharedParam) (*PublicKey, *PrivateKey, error)

	// Encapsulate generates a shared key ss for the public key and
	// encapsulates it into a ciphertext ct.
	Encapsulate(pk PublicKey) (ct, ss []byte, err error)

	// Returns the shared key encapsulated in ciphertext ct for the
	// private key sk.
	Decapsulate(sk PrivateKey, ct []byte) ([]byte, error)

	// Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// Unmarshals a PrivateKey from the provided buffer.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)

	// Size of encapsulated keys.
	CiphertextSize() int

	// Size of established shared keys.
	SharedKeySize() int

	// Size of packed private keys.
	PrivateKeySize() int

	// Size of packed public keys.
	PublicKeySize() int

	// DeriveKeyPair deterministically derives a pair of keys from a seed.
	// Panics if the length of seed is not equal to the value returned by
	// SeedSize.
	DeriveKeyPair(seed []byte) (PublicKey, PrivateKey)

	// Size of seed used in DeriveKey
	SeedSize() int

	// EncapsulateDeterministically generates a shared key ss for the public
	// key deterministically from the given seed and encapsulates it into
	// a ciphertext ct. If unsure, you're better off using Encapsulate().
	EncapsulateDeterministically(pk PublicKey, seed []byte) (
		ct, ss []byte, err error)

	// Size of seed used in EncapsulateDeterministically().
	EncapsulationSeedSize() int
}

// GenerateKeyPair generates a public/private key pair using entropy from rand.
// Paper use the seed from Setup with par := random(Z_q, n x m)
func GenerateKeyPair() (*PublicKey, *PrivateKey, *SharedParam, error) {
	rand := io.Reader(nil)
	pk, sk, ss, err := internal.InitKey(rand)
	if err != nil {
		return nil, nil, nil, err
	}
	return pk, sk, ss, nil
}

// GenerateNewKeyPair generates a public/private key pair using entropy from rand.
func GenerateNewKeyPair(ss SharedParam) (*PublicKey, *PrivateKey, error) {
	rand := io.Reader(nil)
	pk, sk, err := internal.NewKey(rand, ss)
	if err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}
