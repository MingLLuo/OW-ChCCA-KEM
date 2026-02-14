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

// NewKEM creates a new KEM instance with the specified parameters
func NewKEM(params Parameters) KEM {
	return KEM{
		Params: params,
	}
}

// Encapsulate generates a shared key and encapsulates it for the given public key
func Encapsulate(pk *PublicKey) (ciphertext, sharedKey []byte, err error) {
	if pk == nil {
		return nil, nil, pkg.ErrInvalidPublicKey
	}
	kem := NewKEM(pk.Parameters())
	return kem.Encapsulate(pk)
}

// Decapsulate recovers a shared key from a ciphertext using the given private key
func Decapsulate(sk *PrivateKey, ciphertext []byte) (sharedKey []byte, err error) {
	if sk == nil || sk.Public() == nil {
		return nil, pkg.ErrInvalidPrivateKey
	}
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
	if params == nil {
		return nil, pkg.ErrParameterValidation
	}
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
	if pk == nil {
		return nil, pkg.ErrInvalidPublicKey
	}
	sk := PrivateKey{
		Pk: pk,
	}
	if err := sk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &sk, nil
}
