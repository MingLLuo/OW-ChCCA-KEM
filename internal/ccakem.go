package internal

import (
	cryptoRand "crypto/rand"
	"io"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

type (
	Vec []*big.Int
	Mat []Vec
)

type SharedParam struct {
	pRing *ring.Ring
	// with length of N, each element is a Poly with length of M
	PolyVecA []ring.Poly
	A        Mat
}

type PrivateKey struct {
	pRing  *ring.Ring
	PolyZb ring.Poly
	Zb     []*big.Int
	b      bool
}

type PublicKey struct {
	pRing *ring.Ring
	U0    []*big.Int
	U1    []*big.Int
}

// Setup generate n x m BigInt matrix for the key generation, filled with random values
func Setup() Mat {
	pRing, err := ring.NewRing(M, moduli)
	if err != nil {
		panic(err)
	}
	mat := make(Mat, N)
	for i := range mat {
		mat[i] = make(Vec, M)
		for j := range mat[i] {
			mat[i][j], _ = cryptoRand.Int(io.Reader(nil), pRing.Modulus())
		}
	}
	return mat
}

// InitKey This method will Set up First, then generate a key pair
func InitKey(rand io.Reader) (*PublicKey, *PrivateKey, *SharedParam, error) {
	var pk PublicKey
	var sk PrivateKey
	var ss SharedParam

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, nil, err
	}

	// generate single bit b
	b := make([]byte, 1)
	if _, err := io.ReadFull(rand, b); err != nil {
		return nil, nil, nil, err
	}
	sk.b = b[0] == 1

	// Z_b <- Gaussian Z_q, alpha with m x lambda
	pRing, err := ring.NewRing(M, moduli)
	if err != nil {
		panic(err)
	}
	pk.pRing = pRing
	sk.pRing = pRing
	ss.pRing = pRing
	p := pRing.Modulus()
	pFloat, _ := p.Float64()

	samplingPRNG := sampling.PRNG(rand)
	gaussianSampler := ring.NewGaussianSampler(samplingPRNG, pRing, ring.DiscreteGaussian{Sigma: Alpha_, Bound: pFloat}, false)
	// with m row
	sk.PolyZb = gaussianSampler.ReadNew()
	sk.Zb = InitBigIntVec(M)
	pRing.PolyToBigint(sk.PolyZb, 1, sk.Zb)

	// Generate matrix A in Z_q n x m in random, size of A will be n x m x lambda
	// in the following, I will simplify the process
	// 1. use each row of A as a polynomial, multiply with Z_b to get a Vector
	// 2. for each row, calculate the sum mod q to get a Vector(Az_b)
	uniformSampler := ring.NewUniformSampler(samplingPRNG, pRing)
	polyVecA := make([]ring.Poly, N)
	vecPolyAz := make([]ring.Poly, N)
	for i := range N {
		polyVecA[i] = uniformSampler.ReadNew()
		pRing.MulCoeffsBarrett(polyVecA[i], sk.PolyZb, vecPolyAz[i])
	}
	vecAz := make(Vec, N)
	for i := range N {
		coeffs := InitBigIntVec(M)
		pRing.PolyToBigint(vecPolyAz[i], 1, coeffs)
		vecAz[i] = VecSumWithMod(coeffs, p)
	}
	vecZq := make(Vec, N)
	for i := range N {
		vecZq[i], err = cryptoRand.Int(rand, p)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	if sk.b {
		pk.U0 = vecAz
		pk.U1 = vecZq
	} else {
		pk.U0 = vecZq
		pk.U1 = vecAz
	}

	// generate shared key
	ss.PolyVecA = polyVecA
	ss.A = make(Mat, N)
	for i := range N {
		ss.A[i] = InitBigIntVec(M)
		pRing.PolyToBigint(polyVecA[i], 1, ss.A[i])
	}
	return &pk, &sk, &ss, nil
}

func NewKey(rand io.Reader, ss SharedParam) (*PublicKey, *PrivateKey, error) {
	var pk PublicKey
	var sk PrivateKey

	seed := make([]byte, SeedSize)
	_, err := io.ReadFull(rand, seed)
	if err != nil {
		return nil, nil, err
	}

	// generate single bit b
	b := make([]byte, 1)
	if _, err := io.ReadFull(rand, b); err != nil {
		return nil, nil, err
	}
	sk.b = b[0] == 1

	pRing := ss.pRing
	pk.pRing = pRing
	sk.pRing = pRing

	p := pRing.Modulus()
	pFloat, _ := p.Float64()
	samplingPRNG := sampling.PRNG(rand)
	gaussianSampler := ring.NewGaussianSampler(samplingPRNG, pRing, ring.DiscreteGaussian{Sigma: Alpha_, Bound: pFloat}, false)

	// with m row
	sk.PolyZb = gaussianSampler.ReadNew()
	sk.Zb = InitBigIntVec(M)
	pRing.PolyToBigint(sk.PolyZb, 1, sk.Zb)

	// Calculate AZ_b
	polyVecA := ss.PolyVecA
	vecPolyAz := make([]ring.Poly, N)
	for i := range N {
		pRing.MulCoeffsBarrett(polyVecA[i], sk.PolyZb, vecPolyAz[i])
	}
	vecAz := make(Vec, N)
	for i := range N {
		coeffs := InitBigIntVec(M)
		pRing.PolyToBigint(vecPolyAz[i], 1, coeffs)
		vecAz[i] = VecSumWithMod(coeffs, p)
	}

	vecZq := make(Vec, N)
	for i := range N {
		vecZq[i], err = cryptoRand.Int(rand, p)
		if err != nil {
			return nil, nil, err
		}
	}
	if sk.b {
		pk.U0 = vecAz
		pk.U1 = vecZq
	} else {
		pk.U0 = vecZq
		pk.U1 = vecAz
	}

	return &pk, &sk, nil
}
