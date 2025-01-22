package internal

import (
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"github.com/tuneinsight/lattigo/v6/utils/structs"
)

// SampleD will sample from a discrete Gaussian distribution

func SampleD(m int, alpha_ float64, rho *big.Int) Vec {
	// Sample from a discrete Gaussian distribution
	// NewRing creates a new ring with m moduli of the given bit-size, m must be a power of 2 larger than 8.
	newRing, err := ring.NewRing(m, moduli)
	if err != nil {
		panic(err)
	}
	if rho == nil {
		panic("rho is nil")
	}
	p := newRing.Modulus()
	p_float, _ := p.Float64()
	d := ring.DiscreteGaussian{Sigma: alpha_, Bound: p_float}
	prng, err := sampling.NewKeyedPRNG(rho.Bytes())
	sampler, err := ring.NewSampler(prng, newRing, d, false)
	if err != nil {
		panic(err)
	}
	pol := sampler.ReadNew()
	// convert to []big.Int
	coeffs := InitBigIntVec(m)
	newRing.PolyToBigint(pol, 1, coeffs)
	return coeffs
}

// Transpose Matrix
func Transpose(m structs.Matrix[uint64]) structs.Matrix[uint64] {
	mT := structs.Matrix[uint64](make([][]uint64, len(m[0])))
	for i := range mT {
		mT[i] = make([]uint64, len(m))
		for j := range m {
			mT[i][j] = m[j][i]
		}
	}
	return mT
}
