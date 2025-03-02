package pkg

import (
	"fmt"
	"math/big"
)

// BigNTTFriendlyPrimesGenerator generates NTT-friendly primes of arbitrary size
type BigNTTFriendlyPrimesGenerator struct {
	BitSize                        int
	NextPrime, PrevPrime, NthRoot  *big.Int
	CheckNextPrime, CheckPrevPrime bool
}

// NewBigNTTFriendlyPrimesGenerator creates a generator for primes of the form 2^{BitSize} ± k * {NthRoot} + 1
func NewBigNTTFriendlyPrimesGenerator(bitSize int, nthRoot *big.Int) *BigNTTFriendlyPrimesGenerator {
	// Initialize constants
	one := big.NewInt(1)
	twoPowBitSize := new(big.Int).Lsh(one, uint(bitSize))

	// Initialize next prime to 2^BitSize + 1
	nextPrime := new(big.Int).Add(twoPowBitSize, one)

	// Initialize prev prime to 2^BitSize - NthRoot + 1
	prevPrime := new(big.Int).Sub(twoPowBitSize, nthRoot)
	prevPrime.Add(prevPrime, one)

	// Check if prev prime would be valid
	checkPrevPrime := prevPrime.Sign() > 0

	return &BigNTTFriendlyPrimesGenerator{
		BitSize:        bitSize,
		NextPrime:      nextPrime,
		PrevPrime:      prevPrime,
		NthRoot:        new(big.Int).Set(nthRoot),
		CheckNextPrime: true,
		CheckPrevPrime: checkPrevPrime,
	}
}

// NextUpstreamPrime returns the next prime of the form 2^{BitSize} + k * {NthRoot} + 1
func (n *BigNTTFriendlyPrimesGenerator) NextUpstreamPrime() (*big.Int, error) {
	if !n.CheckNextPrime {
		return nil, fmt.Errorf("cannot NextUpstreamPrime: prime list for upstream primes is exhausted")
	}

	// Calculate upper bound to avoid overlap with next bit size
	one := big.NewInt(1)
	twoPowNextBitSize := new(big.Int).Lsh(one, uint(n.BitSize+1))

	for {
		// Check if we've exceeded the bit size limit, TODO: Optimize
		if n.NextPrime.Cmp(twoPowNextBitSize) >= 0 {
			n.CheckNextPrime = false
			return nil, fmt.Errorf("cannot NextUpstreamPrime: prime would exceed bit size limit")
		}

		// Check if the current candidate is prime
		if n.NextPrime.ProbablyPrime(20) {
			// Save result
			result := new(big.Int).Set(n.NextPrime)

			// Move to next candidate
			n.NextPrime.Add(n.NextPrime, n.NthRoot)

			return result, nil
		}

		// Move to next candidate
		n.NextPrime.Add(n.NextPrime, n.NthRoot)
	}
}

// NextDownstreamPrime returns the next prime of the form 2^{BitSize} - k * {NthRoot} + 1
func (n *BigNTTFriendlyPrimesGenerator) NextDownstreamPrime() (*big.Int, error) {
	if !n.CheckPrevPrime {
		return nil, fmt.Errorf("cannot NextDownstreamPrime: prime list for downstream primes is exhausted")
	}

	// Calculate lower bound to avoid overlap with previous bit size
	one := big.NewInt(1)
	twoPowPrevBitSize := new(big.Int).Lsh(one, uint(n.BitSize-1))

	for {
		// Check if we've gone below the previous bit size, TODO: Optimize
		if n.PrevPrime.Cmp(twoPowPrevBitSize) < 0 {
			n.CheckPrevPrime = false
			return nil, fmt.Errorf("cannot NextDownstreamPrime: prime would be below minimum bit size")
		}

		// Check if the current candidate is prime
		if n.PrevPrime.ProbablyPrime(20) {
			// Save result
			result := new(big.Int).Set(n.PrevPrime)

			// Move to next candidate
			n.PrevPrime.Sub(n.PrevPrime, n.NthRoot)

			return result, nil
		}

		// Move to next candidate
		n.PrevPrime.Sub(n.PrevPrime, n.NthRoot)
	}
}

// NextUpstreamPrimes returns the next k primes of the form 2^{BitSize} + k * {NthRoot} + 1
func (n *BigNTTFriendlyPrimesGenerator) NextUpstreamPrimes(k int) ([]*big.Int, error) {
	primes := make([]*big.Int, k)

	for i := range primes {
		prime, err := n.NextUpstreamPrime()
		if err != nil {
			return primes[:i], err
		}
		primes[i] = prime
	}

	return primes, nil
}

// NextDownstreamPrimes returns the next k primes of the form 2^{BitSize} - k * {NthRoot} + 1
func (n *BigNTTFriendlyPrimesGenerator) NextDownstreamPrimes(k int) ([]*big.Int, error) {
	primes := make([]*big.Int, k)

	for i := range primes {
		prime, err := n.NextDownstreamPrime()
		if err != nil {
			return primes[:i], err
		}
		primes[i] = prime
	}

	return primes, nil
}
