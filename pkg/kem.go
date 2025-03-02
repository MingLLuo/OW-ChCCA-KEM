package pkg

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/MingLLuo/OW-ChCCA-KEM/pkg/arithmetic"
	"github.com/tuneinsight/lattigo/v6/ring"
	"io"
	"math/big"

	"github.com/MingLLuo/OW-ChCCA-KEM/pkg/sha3"
)

// Common errors that may be returned
var (
	ErrInvalidPublicKey     = errors.New("owchcca: invalid public key")
	ErrInvalidPrivateKey    = errors.New("owchcca: invalid private key")
	ErrInvalidCiphertext    = errors.New("owchcca: invalid ciphertext")
	ErrDecapsulationFailed  = errors.New("owchcca: decapsulation failed")
	ErrParameterValidation  = errors.New("owchcca: parameter validation failed")
	ErrInvalidRandomSource  = errors.New("owchcca: invalid random source")
	ErrInvalidSharedParams  = errors.New("owchcca: invalid shared parameters")
	ErrSerializationError   = errors.New("owchcca: serialization error")
	ErrDeserializationError = errors.New("owchcca: deserialization error")
)

// OwChCCAKEM implements the KEM interface
type OwChCCAKEM struct {
	Params Parameters
}

// PublicKey represents an OW-ChCCA-KEM public key
type PublicKey struct {
	Params Parameters
	u0     arithmetic.Matrix
	u1     arithmetic.Matrix
	a      arithmetic.Matrix
}

// KEMPrivateKey represents an OW-ChCCA-KEM private key
type PrivateKey struct {
	Pk *PublicKey
	zb arithmetic.Matrix
	b  bool // Flag indicating which matrix contains the authentic data
}

// Bytes returns the serialized form of the public key
func (pk *PublicKey) Bytes() ([]byte, error) {
	var buf bytes.Buffer

	// Write matrix A
	aBytes, err := pk.a.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}
	if _, err = buf.Write(aBytes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}

	// Write matrices U0 and U1
	u0Bytes, err := pk.u0.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}
	if _, err = buf.Write(u0Bytes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}

	u1Bytes, err := pk.u1.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}
	if _, err = buf.Write(u1Bytes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}

	return buf.Bytes(), nil
}

// Parameters return the parameters used by this public key
func (pk *PublicKey) Parameters() Parameters {
	return pk.Params
}

// Equal returns true if the public keys are equal
func (pk *PublicKey) Equal(other *PublicKey) bool {
	otherPK := other

	// Compare parameters
	if pk.Params.Name != otherPK.Params.Name {
		return false
	}

	// Compare matrices
	if !pk.u0.Equal(otherPK.u0) || !pk.u1.Equal(otherPK.u1) || !pk.a.Equal(otherPK.a) {
		return false
	}

	return true
}

// UnmarshalBinary deserializes a public key
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) < pk.Params.KeyParams.PublicKeySize {
		return fmt.Errorf("%w: insufficient data", ErrDeserializationError)
	}

	// Determine sizes based on parameters
	n := pk.Params.LatticeParams.N
	m := pk.Params.LatticeParams.M
	lambda := pk.Params.LatticeParams.Lambda
	modulus := pk.Params.LatticeParams.Q

	// Calculate sizes for each component, with encoded size of matrix
	aSize := 8 + n*m*((modulus.BitLen()+7)/8)
	uSize := 8 + n*lambda*((modulus.BitLen()+7)/8)

	if len(data) < aSize+2*uSize {
		return fmt.Errorf("%w: data too short", ErrDeserializationError)
	}

	// Parse A matrix
	pk.a = arithmetic.NewMatrix(n, m, modulus)
	if err := pk.a.UnmarshalBinary(data[:aSize]); err != nil {
		return fmt.Errorf("%w: %v", ErrDeserializationError, err)
	}

	// Parse U0 matrix
	pk.u0 = arithmetic.NewMatrix(n, lambda, modulus)
	if err := pk.u0.UnmarshalBinary(data[aSize : aSize+uSize]); err != nil {
		return fmt.Errorf("%w: %v", ErrDeserializationError, err)
	}

	// Parse U1 matrix
	pk.u1 = arithmetic.NewMatrix(n, lambda, modulus)
	if err := pk.u1.UnmarshalBinary(data[aSize+uSize : aSize+2*uSize]); err != nil {
		return fmt.Errorf("%w: %v", ErrDeserializationError, err)
	}

	return nil
}

// Bytes returns the serialized form of the private key
func (sk *PrivateKey) Bytes() ([]byte, error) {
	var buf bytes.Buffer

	// Write Zb matrix
	zbBytes, err := sk.zb.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}
	if _, err = buf.Write(zbBytes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}

	// Write b flag
	var bFlag byte
	if sk.b {
		bFlag = 1
	}
	if err := buf.WriteByte(bFlag); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerializationError, err)
	}

	return buf.Bytes(), nil
}

// Public returns the public key corresponding to this private key
func (sk *PrivateKey) Public() *PublicKey {
	return sk.Pk
}

// Equal returns true if the private keys are equal
func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	otherSK := other

	// Compare b flag
	if sk.b != otherSK.b {
		return false
	}

	// Compare matrices
	if !sk.zb.Equal(otherSK.zb) {
		return false
	}

	// Compare public keys
	return sk.Pk.Equal(otherSK.Pk)
}

// UnmarshalBinary deserializes a private key
func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	// Get parameters from public key
	params := sk.Pk.Parameters()
	m := params.LatticeParams.M
	lambda := params.LatticeParams.Lambda
	modulus := params.LatticeParams.Q

	// Calculate expected size
	zbSize := 8 + m*lambda*((modulus.BitLen()+7)/8)
	expectedSize := zbSize + 1 // +1 for the b flag

	if len(data) < expectedSize {
		return fmt.Errorf("%w: insufficient data", ErrDeserializationError)
	}

	// Parse Zb matrix
	sk.zb = arithmetic.NewMatrix(m, lambda, modulus)
	if err := sk.zb.UnmarshalBinary(data[:zbSize]); err != nil {
		return fmt.Errorf("%w: %v", ErrDeserializationError, err)
	}

	// Parse b flag
	sk.b = data[zbSize] == 1

	return nil
}

// PublicKeySize returns the size in bytes of encoded public keys
func (kem *OwChCCAKEM) PublicKeySize() int {
	return kem.Params.KeyParams.PublicKeySize
}

// PrivateKeySize returns the size in bytes of encoded private keys
func (kem *OwChCCAKEM) PrivateKeySize() int {
	return kem.Params.KeyParams.PrivateKeySize
}

// CiphertextSize returns the size in bytes of ciphertexts
func (kem *OwChCCAKEM) CiphertextSize() int {
	return kem.Params.KeyParams.CiphertextSize
}

// SharedKeySize returns the size in bytes of shared keys
func (kem *OwChCCAKEM) SharedKeySize() int {
	return kem.Params.KeyParams.SharedKeySize
}

// GenerateKeyPair generates a key pair using the provided randomness source
func (kem *OwChCCAKEM) GenerateKeyPair(randSource io.Reader) (*PublicKey, *PrivateKey, error) {
	if randSource == nil {
		randSource = rand.Reader
	}

	// Validate parameters
	if err := kem.Params.Validate(); err != nil {
		return nil, nil, err
	}

	// Get parameter values
	n := kem.Params.LatticeParams.N
	m := kem.Params.LatticeParams.M
	lambda := kem.Params.LatticeParams.Lambda
	modulus := kem.Params.LatticeParams.Q
	alpha := kem.Params.GaussianParams.Alpha
	pRing, err := ring.NewRing(m, []uint64{modulus.Uint64()})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ring: %w", err)
	}

	// Generate the shared matrix A
	a := arithmetic.NewMatrix(n, m, modulus)
	uniformSampler := ring.NewUniformSampler(randSource, pRing)
	polyVecA := arithmetic.InitPolyVecWithSampler(n, uniformSampler)
	for i := range n {
		pRing.PolyToBigint(polyVecA[i], 1, a.Values[i])
	}

	// Initialize public and private key structures
	pk := &PublicKey{
		Params: kem.Params,
		a:      a,
	}

	sk := &PrivateKey{
		Pk: pk,
	}

	// Randomly choose b (determining which matrix contains the authentic data)
	bByte := make([]byte, 1)
	if _, err := io.ReadFull(randSource, bByte); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random bit: %w", err)
	}
	sk.b = bByte[0]&1 == 1

	// Sample error matrix Zb from Gaussian distribution
	sk.zb = arithmetic.NewMatrix(m, lambda, modulus)
	gaussianSampler := ring.NewGaussianSampler(randSource, pRing, ring.DiscreteGaussian{Sigma: alpha, Bound: float64(modulus.Int64())}, false)
	PolyVecZbT := arithmetic.InitPolyVecWithSampler(lambda, gaussianSampler)
	for i := range lambda {
		coefficT := arithmetic.NewVector(m, modulus)
		pRing.PolyToBigint(PolyVecZbT[i], 1, coefficT.Values)
		for j := range m {
			sk.zb.Values[j][i] = coefficT.Values[j]
		}
	}

	// Calculate AZ_b, polyVecA size n x m, polyVecZbT size lambda x m
	aZb := arithmetic.NewMatrix(n, lambda, modulus)
	tmpPoly := pRing.NewPoly()
	for i := range n {
		coeffics := arithmetic.NewVector(m, modulus)
		for j := range lambda {
			// Az[i][j] = row i of A * Column j of Zb = Sum(polyVecA[i] * polyVecZbT[j])
			pRing.MulCoeffsBarrett(polyVecA[i], PolyVecZbT[j], tmpPoly)
			pRing.PolyToBigint(tmpPoly, 1, coeffics.Values)
			aZb.Values[i][j] = coeffics.Sum()
		}
	}

	// Generate a random matrix Zq
	zq, err := arithmetic.GenerateRandomMatrix(n, lambda, modulus, randSource)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate random matrix: %w", err)
	}

	// Set U0 and U1 according to b
	if sk.b {
		pk.u1 = aZb
		pk.u0 = zq
	} else {
		pk.u0 = aZb
		pk.u1 = zq
	}

	return pk, sk, nil
}

// Encapsulate generates a shared key and encapsulates it
func (kem *OwChCCAKEM) Encapsulate(pubKey *PublicKey) (ciphertext, sharedKey []byte, err error) {
	pk := pubKey

	// Get parameter values
	n := kem.Params.LatticeParams.N
	m := kem.Params.LatticeParams.M
	lambda := kem.Params.LatticeParams.Lambda
	modulus := kem.Params.LatticeParams.Q
	alphaPrime := kem.Params.GaussianParams.AlphaPrime
	logEta := kem.Params.GaussianParams.LogEta
	sharedKeySize := kem.Params.KeyParams.SharedKeySize

	// Generate random seed r
	r := make([]byte, lambda/8)
	if _, err = io.ReadFull(rand.Reader, r); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	// Expand r to get s, rho, h0, h1 using G function
	s, rho, h0, h1 := expandSeed(r, n, lambda, logEta)
	s.Modulus = modulus

	e, err := arithmetic.GenerateSampleDVector(m, alphaPrime, rho, modulus)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sample error vector: %w", err)
	}

	// Calculate x = A^T*s + e
	at, err := pk.a.Transpose()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to transpose matrix A: %w", err)
	}

	ats, err := at.MultiplyVector(s)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute A^T*s: %w", err)
	}

	x, err := ats.Add(e)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute x = A^T*s + e: %w", err)
	}

	// Calculate hatH0 = U0^T*s + h0*⌊q/2⌋
	u0t, err := pk.u0.Transpose()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to transpose matrix U0: %w", err)
	}

	u0ts, err := u0t.MultiplyVector(s)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute U0^T*s: %w", err)
	}

	hatH0, err := computeHatH(u0ts, h0, modulus)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute hatH0: %w", err)
	}

	// Calculate hatH1 = U1^T*s + h1*⌊q/2⌋
	u1t, err := pk.u1.Transpose()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to transpose matrix U1: %w", err)
	}

	u1ts, err := u1t.MultiplyVector(s)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute U1^T*s: %w", err)
	}

	hatH1, err := computeHatH(u1ts, h1, modulus)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute hatH1: %w", err)
	}

	// Calculate hatK0 = H(x, hatH0, h0)
	hatK0 := hash3(x, hatH0, h0)[:lambda/8]

	// Calculate hatK1 = H(x, hatH1, h1)
	hatK1 := hash3(x, hatH1, h1)[:lambda/8]

	// Calculate c0 = hatK0 ⊕ r
	c0 := make([]byte, lambda/8)
	for i := range c0 {
		c0[i] = hatK0[i] ^ r[i]
	}

	// Calculate c1 = hatK1 ⊕ r
	c1 := make([]byte, lambda/8)
	for i := range c1 {
		c1[i] = hatK1[i] ^ r[i]
	}

	// Construct ciphertext: c0 || c1 || x || hatH0 || hatH1
	ciphertext, err = constructCiphertext(c0, c1, x, hatH0, hatH1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to construct ciphertext: %w", err)
	}

	// Use r as the shared secret (possibly with key derivation)
	sharedKey = kdf(r, sharedKeySize)

	return ciphertext, sharedKey, nil
}

// Decapsulate recovers the shared key from a ciphertext
func (kem *OwChCCAKEM) Decapsulate(privKey *PrivateKey, ciphertext []byte) (sharedKey []byte, err error) {
	sk := privKey
	pk := sk.Pk

	// Get parameter values
	n := kem.Params.LatticeParams.N
	m := kem.Params.LatticeParams.M
	lambda := kem.Params.LatticeParams.Lambda
	logEta := kem.Params.GaussianParams.LogEta
	modulus := kem.Params.LatticeParams.Q
	alphaPrime := kem.Params.GaussianParams.AlphaPrime
	sharedKeySize := kem.Params.KeyParams.SharedKeySize

	// Parse ciphertext
	c0, c1, x, hatH0, hatH1, err := parseCiphertext(ciphertext, m, lambda, modulus)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ciphertext: %w", err)
	}

	// Determine which components to use based on the b flag
	var hatHb, hatHnb *arithmetic.Vector
	var hb, hnb *arithmetic.Vector
	var cb, cnb []byte
	var _, unb arithmetic.Matrix

	if sk.b {
		hatHb, hatHnb = hatH1, hatH0
		cb, cnb = c1, c0
		_, unb = pk.u1, pk.u0
	} else {
		hatHb, hatHnb = hatH0, hatH1
		cb, cnb = c0, c1
		_, unb = pk.u0, pk.u1
	}

	// Calculate Zb^T*x
	zbt, err := sk.zb.Transpose()
	if err != nil {
		return nil, fmt.Errorf("failed to transpose matrix Zb: %w", err)
	}

	zbtx, err := zbt.MultiplyVector(x)
	if err != nil {
		return nil, fmt.Errorf("failed to compute Zb^T*x: %w", err)
	}

	// Calculate hatHb - Zb^T*x
	diff, err := hatHb.Subtract(zbtx)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hatHb - Zb^T*x: %w", err)
	}

	// Round to get hb'
	hbPrime := roundVector(diff, modulus)

	// Calculate hatKb = H(x, hatHb, hb')
	hatKb := hash3(x, hatHb, hbPrime)[:lambda/8]

	// Recover r = cb ⊕ hatKb
	r := make([]byte, lambda/8)
	for i := range r {
		r[i] = cb[i] ^ hatKb[i]
	}

	// Expand r to get s, rho, h0, h1
	s, rho, h0, h1 := expandSeed(r, n, lambda, logEta)
	s.Modulus = modulus

	// Determine which h values to use
	if sk.b {
		hb, hnb = h1, h0
	} else {
		hb, hnb = h0, h1
	}

	// Calculate hatHnb' = Unb^T*s + hnb*⌊q/2⌋
	unbt, err := unb.Transpose()
	if err != nil {
		return nil, fmt.Errorf("failed to transpose matrix Unb: %w", err)
	}

	unbts, err := unbt.MultiplyVector(s)
	if err != nil {
		return nil, fmt.Errorf("failed to compute Unb^T*s: %w", err)
	}

	hatHnbPrime, err := computeHatH(unbts, hnb, modulus)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hatHnb': %w", err)
	}

	// Calculate hatKnb = H(x, hatHnb', hnb)
	hatKnb := hash3(x, hatHnbPrime, hnb)[:lambda/8]

	e, err := arithmetic.GenerateSampleDVector(m, alphaPrime, rho, modulus)
	if err != nil {
		return nil, fmt.Errorf("failed to sample error vector: %w", err)
	}

	// Calculate x' = A^T*s + e
	at, err := pk.a.Transpose()
	if err != nil {
		return nil, fmt.Errorf("failed to transpose matrix A: %w", err)
	}

	ats, err := at.MultiplyVector(s)
	if err != nil {
		return nil, fmt.Errorf("failed to compute A^T*s: %w", err)
	}

	xPrime, err := ats.Add(e)
	if err != nil {
		return nil, fmt.Errorf("failed to compute x' = A^T*s + e: %w", err)
	}

	// Verify that x' = x
	if !x.Equal(xPrime) {
		return nil, ErrDecapsulationFailed
	}

	// Verify that hatKnb ⊕ r = cnb
	cnbCalculated := make([]byte, lambda/8)
	for i := range cnbCalculated {
		cnbCalculated[i] = hatKnb[i] ^ r[i]
	}

	if subtle.ConstantTimeCompare(cnb, cnbCalculated) != 1 {
		return nil, ErrDecapsulationFailed
	}

	// Verify that hb' = hb
	if !hbPrime.Equal(hb) {
		return nil, ErrDecapsulationFailed
	}

	// Verify that hatHnb' = hatHnb
	if !hatHnbPrime.Equal(hatHnb) {
		return nil, ErrDecapsulationFailed
	}

	// Use r as the shared secret (possibly with key derivation)
	sharedKey = kdf(r, sharedKeySize)

	return sharedKey, nil
}

// expandSeed expands a seed into s, rho, h0, h1 using a hash function
func expandSeed(seed []byte, n, lambda, logEta int) (*arithmetic.Vector, []byte, *arithmetic.Vector, *arithmetic.Vector) {
	// Use SHA3-256 as the hash function
	h := sha3.New256()
	h.Write(seed)
	m := h.Sum(nil)

	// Use SHA3-512 for expansion
	h = sha3.New512()
	h.Write(m)

	// Calculate sizes
	sSize := n * (logEta + 1) / 8
	rhoSize := lambda / 8
	h0Size := lambda / 8
	h1Size := lambda / 8

	// Generate all randomness in one go
	totalSize := sSize + rhoSize + h0Size + h1Size
	expandedBytes := make([]byte, totalSize)
	h.Read(expandedBytes)

	// Split into components
	sBits := expandedBytes[:sSize]
	rho := expandedBytes[sSize : sSize+rhoSize]
	h0Bits := expandedBytes[sSize+rhoSize : sSize+rhoSize+h0Size]
	h1Bits := expandedBytes[sSize+rhoSize+h0Size:]

	// Convert s to a vector
	s := bytesToVector(sBits, n, logEta+1)

	// Convert h0 and h1 to vectors
	h0 := bytesToBinaryVector(h0Bits, lambda)
	h1 := bytesToBinaryVector(h1Bits, lambda)

	return s, rho, h0, h1
}

// bytesToVector converts byte array to a vector, interpreting groups of bits
func bytesToVector(data []byte, length, bitsPerValue int) *arithmetic.Vector {
	totalBitsNeeded := length * bitsPerValue
	if len(data)*8 < totalBitsNeeded {
		return nil
	}

	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bitsPerValue)), big.NewInt(1))
	result := arithmetic.NewVector(length, mask)

	for i := 0; i < length; i++ {
		startBit := i * bitsPerValue
		startByte := startBit / 8
		bitOffset := startBit % 8

		value := big.NewInt(0)
		bitsRemaining := bitsPerValue
		currentBitOffset := bitOffset

		// Read bytes until we have all bits for this element
		for j := startByte; bitsRemaining > 0; j++ {
			if j >= len(data) {
				break
			}

			// Number of bits to read from this byte
			bitsToRead := 8 - currentBitOffset
			if bitsToRead > bitsRemaining {
				bitsToRead = bitsRemaining
			}

			// Extract bits and add to value
			byteMask := byte((1 << bitsToRead) - 1)
			extracted := (data[j] >> currentBitOffset) & byteMask

			value.Lsh(value, uint(bitsToRead))
			value.Or(value, big.NewInt(int64(extracted)))

			bitsRemaining -= bitsToRead
			currentBitOffset = 0
		}
		value.And(value, mask)
		result.Set(i, value)
	}

	return result
}

// bytesToBinaryVector converts byte array to a binary vector (0 or 1 entries)
func bytesToBinaryVector(data []byte, length int) *arithmetic.Vector {
	result := arithmetic.NewVector(length, big.NewInt(1))
	if len(data)*8 < length {
		return nil
	}

	for i := 0; i < length; i++ {
		byteIndex := i / 8
		bitOffset := i % 8

		bitValue := (data[byteIndex] >> bitOffset) & 1
		if bitValue == 1 {
			result.Set(i, big.NewInt(1))
		} else {
			result.Set(i, big.NewInt(0))
		}
	}

	return result
}

// hash3 computes H(x, hatH, h)
func hash3(x, hatH, h *arithmetic.Vector) []byte {
	// Use SHA3-256 as the hash function
	hash := sha3.New256()

	// Serialize and write x
	xBytes, _ := x.MarshalBinary()
	hash.Write(xBytes)

	// Serialize and write hatH
	hatHBytes, _ := hatH.MarshalBinary()
	hash.Write(hatHBytes)

	// Serialize and write h
	hBytes, _ := h.MarshalBinary()
	hash.Write(hBytes)

	// Return the hash
	return hash.Sum(nil)
}

// computeHatH calculates U^T*s + h*⌊q/2⌋
func computeHatH(uTs, h *arithmetic.Vector, modulus *big.Int) (*arithmetic.Vector, error) {
	// Calculate ⌊q/2⌋
	halfQ := new(big.Int).Rsh(modulus, 1)

	// Scale h by ⌊q/2⌋
	scaled, err := h.ScalarMultiply(halfQ)
	if err != nil {
		return nil, err
	}

	// Add to U^T*s
	result, err := uTs.Add(scaled)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// roundVector rounds each component of a vector
func roundVector(v *arithmetic.Vector, modulus *big.Int) *arithmetic.Vector {
	// Calculate ⌊q/2⌋
	halfQ := new(big.Int).Rsh(modulus, 1)

	// Create result vector
	length := v.Length()
	result := arithmetic.NewVector(length, big.NewInt(1))

	// Round each component
	for i := 0; i < length; i++ {
		val := v.Get(i)

		// Compute distance to 0 and halfQ
		distToZero := new(big.Int).Set(val)
		if distToZero.Cmp(halfQ) > 0 {
			distToZero.Sub(modulus, distToZero)
		}

		distToHalfQ := new(big.Int).Sub(val, halfQ)
		if distToHalfQ.Sign() < 0 {
			distToHalfQ.Neg(distToHalfQ)
		}

		// Round to closer value
		if distToZero.Cmp(distToHalfQ) <= 0 {
			result.Set(i, big.NewInt(0))
		} else {
			result.Set(i, big.NewInt(1))
		}
	}

	return result
}

// constructCiphertext constructs the full ciphertext
func constructCiphertext(c0, c1 []byte, x, hatH0, hatH1 *arithmetic.Vector) ([]byte, error) {
	var buf bytes.Buffer

	// Write c0
	if _, err := buf.Write(c0); err != nil {
		return nil, err
	}

	// Write c1
	if _, err := buf.Write(c1); err != nil {
		return nil, err
	}

	// Serialize and write x
	xBytes, err := x.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err := buf.Write(xBytes); err != nil {
		return nil, err
	}

	// Serialize and write hatH0
	hatH0Bytes, err := hatH0.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err := buf.Write(hatH0Bytes); err != nil {
		return nil, err
	}

	// Serialize and write hatH1
	hatH1Bytes, err := hatH1.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err := buf.Write(hatH1Bytes); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// parseCiphertext parses the components of a ciphertext
func parseCiphertext(ciphertext []byte, m, lambda int, modulus *big.Int) (c0, c1 []byte, x, hatH0, hatH1 *arithmetic.Vector, err error) {
	if len(ciphertext) < 2*(lambda/8) {
		return nil, nil, nil, nil, nil, fmt.Errorf("%w: ciphertext too short", ErrInvalidCiphertext)
	}

	// Read c0 and c1
	c0 = ciphertext[:lambda/8]
	c1 = ciphertext[lambda/8 : 2*(lambda/8)]

	// Determine position after c0 and c1
	pos := 2 * (lambda / 8)

	// Parse x
	x = arithmetic.NewVector(m, modulus)
	xSize := x.EncodedSize()
	if len(ciphertext) < pos+xSize {
		return nil, nil, nil, nil, nil, fmt.Errorf("%w: ciphertext too short for x", ErrInvalidCiphertext)
	}
	if err := x.UnmarshalBinary(ciphertext[pos : pos+xSize]); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("%w: failed to parse x: %v", ErrInvalidCiphertext, err)
	}
	pos += xSize

	// Parse hatH0
	hatH0 = arithmetic.NewVector(lambda, modulus)
	hSize := hatH0.EncodedSize()
	if len(ciphertext) < pos+hSize {
		return nil, nil, nil, nil, nil, fmt.Errorf("%w: ciphertext too short for hatH0", ErrInvalidCiphertext)
	}
	if err := hatH0.UnmarshalBinary(ciphertext[pos : pos+hSize]); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("%w: failed to parse hatH0: %v", ErrInvalidCiphertext, err)
	}
	pos += hSize

	// Parse hatH1
	hatH1 = arithmetic.NewVector(lambda, modulus)
	if len(ciphertext) < pos+hSize {
		return nil, nil, nil, nil, nil, fmt.Errorf("%w: ciphertext too short for hatH1", ErrInvalidCiphertext)
	}
	if err := hatH1.UnmarshalBinary(ciphertext[pos : pos+hSize]); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("%w: failed to parse hatH1: %v", ErrInvalidCiphertext, err)
	}

	return c0, c1, x, hatH0, hatH1, nil
}

// kdf applies a key derivation function to derive the final key
func kdf(input []byte, outputSize int) []byte {
	// Use SHA3-512 for key derivation
	hash := sha3.New512()
	hash.Write(input)
	hash.Write([]byte("OW-ChCCA-KEM-KDF"))

	// For longer keys, we can iterate the hash function
	output := make([]byte, outputSize)
	hash.Read(output)
	return output
}
