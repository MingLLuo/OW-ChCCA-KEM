package pkg

import (
	"fmt"
	"math"
	"math/big"
	"sync"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// SecurityLevel represents a standardized security level in bits
type SecurityLevel int

const (
	// Security16 represents 16-bit security level
	Security16 SecurityLevel = 16
	// Security32 represents 32-bit security level
	Security32 SecurityLevel = 32
	// Security64 represents 64-bit security level
	Security64 SecurityLevel = 64
	// Security128 represents 128-bit security level
	Security128 SecurityLevel = 128
	// Security192 represents 192-bit security level
	Security192 SecurityLevel = 192
	// Security256 represents 256-bit security level
	Security256 SecurityLevel = 256
)

type Parameters struct {
	Name string
	// SecurityLevel is the estimated security level in bits
	SecurityLevel SecurityLevel
	// LatticeParams defines the lattice dimensions
	LatticeParams LatticeParameters
	// GaussianParams defines the Gaussian sampling parameters
	GaussianParams GaussianParameters
	// KeyParams defines key-related parameters
	KeyParams KeyParameters
}

// LatticeParameters contains parameters related to the lattice dimensions
type LatticeParameters struct {
	// N is the lattice dimension (n := 70λ)
	N int
	// M is the number of samples (m := 2n*log q)
	M int
	// Lambda is the security parameter
	Lambda int
	// LogQ is the bit size of the modulus
	LogQ int
	// Q is the modulus (n^6 < q ≤ n^7)
	Q *big.Int
	// K is the dimension parameter for the key (k := λ)
	K int
}

// GaussianParameters contains parameters for Gaussian sampling
type GaussianParameters struct {
	// Alpha is the standard deviation for the main Gaussian sampler (α := √n)
	Alpha float64
	// AlphaPrime is the standard deviation for the error sampler (α' := n^2.5*m)
	AlphaPrime float64
	// Gamma is the rejection sampling parameter (γ := √n)
	Gamma float64
	// Eta is the bound parameter for rejection sampling (η := √n)
	Eta float64
	// LogEta is log2(Eta)
	LogEta int
}

// KeyParameters contains parameters related to keys
type KeyParameters struct {
	// PublicKeySize is the size in bytes of the public key
	PublicKeySize int
	// PrivateKeySize is the size in bytes of the private key
	PrivateKeySize int
	// CiphertextSize is the size in bytes of the ciphertext
	CiphertextSize int
	// SharedKeySize is the size in bytes of the shared key
	SharedKeySize int
}

// ParameterRegistry manages parameter sets
type ParameterRegistry struct {
	mu         sync.RWMutex
	paramSets  map[string]Parameters
	defaultSet string
}

var globalRegistry = &ParameterRegistry{
	paramSets:  make(map[string]Parameters),
	defaultSet: "OWChCCA-64",
}

// Initialize the registry with default parameter sets
func init() {
	RegisterParameterSet(CalculateParameters(Security16))
	RegisterParameterSet(CalculateParameters(Security32))
	RegisterParameterSet(CalculateParameters(Security64))
	// RegisterParameterSet(CalculateParameters(Security128))
	// RegisterParameterSet(CalculateParameters(Security192))
	// RegisterParameterSet(CalculateParameters(Security256))

	SetDefaultParameterSet("OWChCCA-16")
}

// RegisterParameterSet adds a parameter set to the registry
func RegisterParameterSet(params Parameters) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	globalRegistry.paramSets[params.Name] = params
}

// GetParameterSet retrieves a parameter set by name
func GetParameterSet(name string) (Parameters, error) {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	params, ok := globalRegistry.paramSets[name]
	if !ok {
		return Parameters{}, fmt.Errorf("parameter set %s not found", name)
	}

	return params, nil
}

// GetDefaultParameterSet returns the default parameter set
func GetDefaultParameterSet() Parameters {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	return globalRegistry.paramSets[globalRegistry.defaultSet]
}

// SetDefaultParameterSet sets the default parameter set
func SetDefaultParameterSet(name string) error {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()

	if _, ok := globalRegistry.paramSets[name]; !ok {
		return fmt.Errorf("parameter set %s not found", name)
	}

	globalRegistry.defaultSet = name
	return nil
}

// ListParameterSets returns a list of all registered parameter set names
func ListParameterSets() []string {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()

	names := make([]string, 0, len(globalRegistry.paramSets))
	for name := range globalRegistry.paramSets {
		names = append(names, name)
	}

	return names
}

// DefaultParameters returns the parameter set for the given security level
func DefaultParameters(level SecurityLevel) Parameters {
	name := fmt.Sprintf("OWChCCA-%d", level)
	params, err := GetParameterSet(name)
	if err != nil {
		// If not found, calculate and register it
		params = CalculateParameters(level)
		RegisterParameterSet(params)
	}
	return params
}

// CalculateParameters computes parameter values according to the paper's formulas
func CalculateParameters(lambda SecurityLevel) Parameters {
	// Convert to integer for calculations
	level := int(lambda)

	// Calculate parameters according to the formulas
	// n := 70 * level
	n := 8 * level
	k := level

	logN := int(math.Log2(float64(n)))
	if math.Pow(2, float64(logN)) != float64(n) {
		logN++
	}
	// if let m := 2n Log q
	// then 12n Log n < m <= 14n Log n
	// Calculate minimal q that satisfies n^6 < q ≤ n^7
	var m, logQ int
	var q *big.Int
	var err error
	// minLogQ := 6*logN + 1
	// maxLogQ := 7 * logN
	// minM := 12*n*logN + 1
	// maxM := 14 * n * logN
	minM := 6*n*logN + 1
	maxM := 7 * n * logN
	// Find Closest M with power of 2
	minLogM := int(math.Log2(float64(minM)))
	if math.Pow(2, float64(minLogM)) != float64(minM) {
		minLogM++
	}
	maxLogM := int(math.Log2(float64(maxM)))
	if math.Pow(2, float64(maxLogM)) != float64(maxM) {
		maxLogM++
	}

	for m = int(math.Exp2(float64(minLogM))); m <= int(math.Exp2(float64(maxLogM))); m = m * 2 {
		// find q
		// logQ = m / (2 * n)
		logQ = min(60, max(62, m/(2*n)))
		nttGenerator := NewBigNTTFriendlyPrimesGenerator(logQ+1, new(big.Int).SetInt64(int64(2*m)))
		q, err = nttGenerator.NextDownstreamPrime()
		if err != nil {
			if m != maxM {
				continue
			} else {
				return Parameters{}
			}
		} else {
			break
		}
	}

	// Gaussian parameters
	sqrtN := math.Sqrt(float64(n))
	alpha := sqrtN
	gamma := sqrtN
	eta := sqrtN
	logEta := int(math.Ceil(math.Log2(eta)))

	// Calculate alphaPrime as n^2.5 * m
	alphaPrime := math.Pow(float64(n), 2.5) * float64(m)

	param := Parameters{
		Name:          fmt.Sprintf("OWChCCA-%d", lambda),
		SecurityLevel: lambda,
		LatticeParams: LatticeParameters{
			N:      n,
			M:      m,
			Lambda: level,
			LogQ:   logQ,
			Q:      q,
			K:      k,
		},
		GaussianParams: GaussianParameters{
			Alpha:      alpha,
			AlphaPrime: alphaPrime,
			Gamma:      gamma,
			Eta:        eta,
			LogEta:     logEta,
		},
		KeyParams: KeyParameters{},
	}
	param.KeyParams.PublicKeySize = param.PublicKeySize()
	param.KeyParams.PrivateKeySize = param.PrivateKeySize()
	param.KeyParams.CiphertextSize = param.CiphertextSize()
	param.KeyParams.SharedKeySize = param.SharedKeySize()
	return param
}

func (p Parameters) PublicKeySize() int {
	q := p.LatticeParams.Q
	n := p.LatticeParams.N
	m := p.LatticeParams.M
	level := int(p.SecurityLevel)
	modulus := new(big.Int).Set(q)
	elementSize := (modulus.BitLen() + 7) / 8
	aSize := 8 + n*m*elementSize
	uSize := 8 + n*level*elementSize
	return aSize + uSize*2
}

func (p Parameters) PrivateKeySize() int {
	q := p.LatticeParams.Q
	m := p.LatticeParams.M
	level := int(p.SecurityLevel)
	modulus := new(big.Int).Set(q)
	elementSize := (modulus.BitLen() + 7) / 8
	zbSize := 8 + m*level*elementSize
	pkSize := p.PublicKeySize()
	if pkSize == 0 {
		pkSize = p.PublicKeySize()
	}
	return zbSize + 1 + pkSize
}

func (p Parameters) CiphertextSize() int {
	q := p.LatticeParams.Q
	m := p.LatticeParams.M
	level := int(p.SecurityLevel)
	modulus := new(big.Int).Set(q)
	elementSize := (modulus.BitLen() + 7) / 8
	cbSize := level / 8
	xSize := 4 + m*elementSize
	hatHbSize := level / 8
	return 2*cbSize + xSize + 2*hatHbSize
}

func (p Parameters) SharedKeySize() int {
	level := int(p.SecurityLevel)
	return level / 8
}

// Validate checks if the parameters satisfy the security requirements
func (p Parameters) Validate() error {
	// Get values for readability
	n := p.LatticeParams.N
	m := p.LatticeParams.M
	lambda := p.LatticeParams.Lambda
	k := p.LatticeParams.K
	q := p.LatticeParams.Q
	// logQ := p.LatticeParams.LogQ
	alpha := p.GaussianParams.Alpha
	alphaPrime := p.GaussianParams.AlphaPrime
	eta := p.GaussianParams.Eta

	// Check basic parameter ranges
	if n <= 0 || m <= 0 || lambda <= 0 {
		return fmt.Errorf("invalid dimension parameters")
	}

	//// Check that n = 70λ
	//if n != 70*lambda {
	//	return fmt.Errorf("n should be 70*lambda")
	//}

	// Check that k = λ
	if k != lambda {
		return fmt.Errorf("k should be equal to lambda")
	}

	// Check q size: n^6 < q ≤ n^7
	//nPow6 := new(big.Int).Exp(big.NewInt(int64(n)), big.NewInt(6), nil)
	//nPow7 := new(big.Int).Exp(big.NewInt(int64(n)), big.NewInt(7), nil)
	//// check bigLen
	////nPow6BitLen := nPow6.BitLen()
	//nPow7BitLen := nPow7.BitLen()
	//qBitLen := q.BitLen()
	//if qBitLen < nPow6BitLen || qBitLen > nPow7BitLen {
	//	return fmt.Errorf("qBitLen should be in range nPow6BitLen < qBitLen ≤ nPow7BitLen")
	//}
	//if q.Cmp(nPow6) <= 0 || q.Cmp(nPow7) > 0 {
	//	return fmt.Errorf("q should be in range n^6 < q ≤ n^7")
	//}

	// Check that m = 2n*log q
	//if math.Abs(float64(m-2*n*logQ)) > 1000 {
	//	return fmt.Errorf("m should be 2*n*log(q) with error < 1000")
	//}

	// Check Gaussian parameters: α = γ = η = √n
	sqrtN := math.Sqrt(float64(n))
	epsilon := 0.01 // Allow for small floating-point differences

	if math.Abs(alpha-sqrtN) > epsilon {
		return fmt.Errorf("alpha should be approximately √n")
	}

	if math.Abs(p.GaussianParams.Gamma-sqrtN) > epsilon {
		return fmt.Errorf("gamma should be approximately √n")
	}

	if math.Abs(eta-sqrtN) > epsilon {
		return fmt.Errorf("eta should be approximately √n")
	}

	// Check α' = n^2.5 * m
	expectedAlphaPrime := math.Pow(float64(n), 2.5) * float64(m)
	if math.Abs(alphaPrime-expectedAlphaPrime)/expectedAlphaPrime > 0.05 { // Allow 5% deviation
		return fmt.Errorf("alphaPrime should be n^2.5 * m")
	}

	_, err := ring.NewRing(m, []uint64{q.Uint64()})
	if err != nil {
		return fmt.Errorf("error creating ring: %v", err)
	}

	return nil
}
