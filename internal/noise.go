package internal

import (
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
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
	pFloat, _ := p.Float64()
	d := ring.DiscreteGaussian{Sigma: alpha_, Bound: pFloat}
	prng, err := sampling.NewKeyedPRNG(rho.Bytes())
	sampler, err := ring.NewSampler(prng, newRing, d, false)
	if err != nil {
		panic(err)
	}
	pol := sampler.ReadNew()
	coeffs := InitBigIntVec(m)
	newRing.PolyToBigint(pol, 1, coeffs)
	return coeffs
}
