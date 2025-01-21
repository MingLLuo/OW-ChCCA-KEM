package internal

const (
	// Size of seed for NewKeyFromSeed
	KeySeedSize = 32

	// Size of seed for EncapsulateTo.
	EncapsulationSeedSize = 32

	// Size of the established shared key.
	SharedKeySize = Lambda

	// Size of the encapsulated shared key.
	// c0 + c1 + x + hatH0 + hatH1
	// InBytes, Lambda/8 + Lambda/8 + M * Lambda/8 + N * Lambda/8 + N * Lambda/8
	CiphertextSize = Lambda * (2 + M + 2*N)

	// Size of a packed public key.
	PublicKeySize = 32

	// Size of a packed private key.
	PrivateKeySize = 32

	// Size of a packed pk.U matrix
	UMatrixSize = N * Lambda * Lambda / 8
)

//const (
//	SeedSize = 32
//	// 2^6
//	Lambda = 64
//	K      = Lambda
//	// sqrt(N) = 67
//	N = 70 * Lambda
//	// Approximate 70 * 64 -> 2^12, 6 * 12 = 72, 7 * 12 = 84 -> 80
//	QLen = 80
//	M    = 2 * N * QLen
//	// sqrt(2^6 * 70) = 66 -> 64
//	Alpha  = 64
//	Eta    = 64
//	Log2Eta = 6
//	// Alpha_ 2^(2.5*10) * 2^16
//	Alpha_ = N * N * M * 67
//)

const (
	SeedSize = 32
	Lambda   = 16
	K        = Lambda
	// sqrt(N) = 32
	N = 64 * Lambda
	// Approximate 64 * 16 -> 2^10, 6 * 10 = 60, 7 * 10 = 70 -> 64
	QLen    = 64
	M       = 2 * N * QLen
	Alpha   = 32
	Eta     = 32
	Log2Eta = 5
	Alpha_  = N * N * M * 32
)

type Parameters struct {
	logN uint64
	qi   []uint64
	pi   []uint64
}

var testParameters = Parameters{
	10, Qi60[len(Qi60)-14:], Pi60[len(Pi60)-14:],
}

// Qi60 are the first [0:32] 61-bit close to 2^{62} NTT-friendly primes for N up to 2^{17}
var Qi60 = []uint64{
	0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001,
	0x1fffffffff380001, 0x1fffffffff000001, 0x1ffffffffef00001, 0x1ffffffffee80001,
	0x1ffffffffeb40001, 0x1ffffffffe780001, 0x1ffffffffe600001, 0x1ffffffffe4c0001,
	0x1ffffffffdf40001, 0x1ffffffffdac0001, 0x1ffffffffda40001, 0x1ffffffffc680001,
	0x1ffffffffc000001, 0x1ffffffffb880001, 0x1ffffffffb7c0001, 0x1ffffffffb300001,
	0x1ffffffffb1c0001, 0x1ffffffffadc0001, 0x1ffffffffa400001, 0x1ffffffffa140001,
	0x1ffffffff9d80001, 0x1ffffffff9140001, 0x1ffffffff8ac0001, 0x1ffffffff8a80001,
	0x1ffffffff81c0001, 0x1ffffffff7800001, 0x1ffffffff7680001, 0x1ffffffff7080001,
}

// Pi60 are the next [32:64] 61-bit close to 2^{62} NTT-friendly primes for N up to 2^{17}
var Pi60 = []uint64{
	0x1ffffffff6c80001, 0x1ffffffff6140001, 0x1ffffffff5f40001, 0x1ffffffff5700001,
	0x1ffffffff4bc0001, 0x1ffffffff4380001, 0x1ffffffff3240001, 0x1ffffffff2dc0001,
	0x1ffffffff1a40001, 0x1ffffffff11c0001, 0x1ffffffff0fc0001, 0x1ffffffff0d80001,
	0x1ffffffff0c80001, 0x1ffffffff08c0001, 0x1fffffffefd00001, 0x1fffffffef9c0001,
	0x1fffffffef600001, 0x1fffffffeef40001, 0x1fffffffeed40001, 0x1fffffffeed00001,
	0x1fffffffeebc0001, 0x1fffffffed540001, 0x1fffffffed440001, 0x1fffffffed2c0001,
	0x1fffffffed200001, 0x1fffffffec940001, 0x1fffffffec6c0001, 0x1fffffffebe80001,
	0x1fffffffebac0001, 0x1fffffffeba40001, 0x1fffffffeb4c0001, 0x1fffffffeb280001,
}

var moduli = testParameters.pi
