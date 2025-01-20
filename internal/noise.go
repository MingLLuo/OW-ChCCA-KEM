package internal

import (
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"github.com/tuneinsight/lattigo/v6/utils/structs"
	"golang.org/x/exp/rand"
	"gonum.org/v1/gonum/stat/distuv"
)

// SampleD will sample from a discrete Gaussian distribution

func SampleD(m int, alpha_ float64, rho sampling.PRNG) (structs.Matrix[uint64], big.Int) {
	// Sample from a discrete Gaussian distribution
	// NewRing creates a new ring with m moduli of the given bit-size, m must be a power of 2 larger than 8.
	// make p to []uint64
	newRing, err := ring.NewRing(m, moduli)
	if err != nil {
		panic(err)
	}
	p := newRing.Modulus()
	p_float, _ := p.Float64()
	d := ring.DiscreteGaussian{Sigma: alpha_, Bound: p_float}
	sampler, err := ring.NewSampler(rho, newRing, d, false)
	if err != nil {
		panic(err)
	}
	pol := sampler.ReadNew()
	return Transpose(pol.Coeffs), *p
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

func SampleD1(m int, alpha_ float64, rho rand.Source) []uint64 {
	// Sample from a discrete Gaussian distribution
	d := distuv.Normal{Mu: 0, Sigma: alpha_, Src: rho}
	samples := make([]uint64, m)
	for i := 0; i < m; i++ {
		samples[i] = uint64(d.Rand())
	}
	return samples
}
