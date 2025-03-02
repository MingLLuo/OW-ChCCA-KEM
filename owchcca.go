package owchcca

import (
	"crypto/rand"

	"github.com/MingLLuo/OW-ChCCA-KEM/pkg"
)

type (
	KEM        = pkg.OwChCCAKEM
	PublicKey  = pkg.PublicKey
	PrivateKey = pkg.PrivateKey
	Parameters = pkg.Parameters
)

// KEM defines the interface for a key encapsulation mechanism
//type KEM interface {
//	// Encapsulate generates a shared key and encapsulates it
//	Encapsulate(pk PublicKey) (ciphertext, sharedKey []byte, err error)
//
//	// Decapsulate recovers the shared key from a ciphertext
//	Decapsulate(sk PrivateKey, ciphertext []byte) (sharedKey []byte, err error)
//
//	// PublicKeySize returns the size in bytes of encoded public keys
//	PublicKeySize() int
//
//	// PrivateKeySize returns the size in bytes of encoded private keys
//	PrivateKeySize() int
//
//	// CiphertextSize returns the size in bytes of ciphertexts
//	CiphertextSize() int
//
//	// SharedKeySize returns the size in bytes of shared keys
//	SharedKeySize() int
//
//	// GenerateKeyPair generates a key pair using the provided randomness source
//	GenerateKeyPair(rand io.Reader) (PublicKey, PrivateKey, error)
//}
// PublicKey represents an OW-ChCCA-KEM public key
//type PublicKey interface {
//	// Bytes returns the serialized form of the public key
//	Bytes() ([]byte, error)
//
//	// Parameters returns the parameters used by this public key
//	Parameters() pkg.Parameters
//
//	// Equal returns true if the public keys are equal
//	Equal(PublicKey) bool
//}

// PrivateKey represents an OW-ChCCA-KEM private key
//type PrivateKey interface {
//	// Bytes returns the serialized form of the private key
//	Bytes() ([]byte, error)
//
//	// Public returns the public key corresponding to this private key
//	Public() PublicKey
//
//	// Equal returns true if the private keys are equal
//	Equal(PrivateKey) bool
//}

// NewKEM creates a new KEM instance with the specified parameters
func NewKEM(params Parameters) KEM {
	return KEM{
		Params: params,
	}
}

// Encapsulate generates a shared key and encapsulates it for the given public key
func Encapsulate(pk *PublicKey) (ciphertext, sharedKey []byte, err error) {
	kem := NewKEM(pk.Parameters())
	return kem.Encapsulate(pk)
}

// Decapsulate recovers a shared key from a ciphertext using the given private key
func Decapsulate(sk *PrivateKey, ciphertext []byte) (sharedKey []byte, err error) {
	public := sk.Public()
	kem := NewKEM(public.Parameters())
	return kem.Decapsulate(sk, ciphertext)
}

// GenerateKeyPair generates a new key pair with the specified parameters
func GenerateKeyPair(params Parameters) (*PublicKey, *PrivateKey, error) {
	kem := NewKEM(params)
	return kem.GenerateKeyPair(rand.Reader)
}

// ParsePublicKey parses a serialized public key
func ParsePublicKey(data []byte, params *Parameters) (*PublicKey, error) {
	pk := PublicKey{
		Params: *params,
	}
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &pk, nil
}

// ParsePrivateKey parses a serialized private key
func ParsePrivateKey(data []byte, pk *PublicKey) (*PrivateKey, error) {
	sk := PrivateKey{
		Pk: pk,
	}
	if err := sk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &sk, nil
}
