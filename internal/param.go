package internal

const (
	// Size of seed for NewKeyFromSeed
	KeySeedSize = 32

	// Size of seed for EncapsulateTo.
	EncapsulationSeedSize = 32

	// Size of the established shared key.
	SharedKeySize = Lambda

	SharedParamSize = N * M * QLen

	// Size of the encapsulated shared key.
	// c0 + c1 + x + hatH0 + hatH1
	// Lambda + Lambda + M x QLen + Lambda x QLen + Lambda x QLen
	// InBytes, Lambda/8 + Lambda/8 + M * QLen/8 + N * Lambda/8 + N * Lambda/8
	CiphertextSize = 2*Lambda + M*QLen + 2*Lambda*QLen

	// Size of a packed public key.
	PublicKeySize = UMatrixSize * 2

	// Size of a packed private key, with one bit to be a byte aligned.
	PrivateKeySize = MatZbSize + 8

	// Size of a packed pk.U matrix
	UMatrixSize = N * Lambda * QLen
	MatZbSize   = M * Lambda * QLen
)

const (
	SeedSize = 32
	Lambda   = 64
	sqrtN    = 4
	Log2N    = 4
	Log2Eta  = 5
	K        = Lambda
	N        = sqrtN * sqrtN
	QMin     = N * N * N * N * N * N
	QMax     = N * QMin
	//QLen = Log2N * 6
	QLen = 24
	// M       = 2 * N * QLen
	M      = 16
	Alpha  = sqrtN
	Eta    = 1 << Log2Eta
	Alpha_ = N * N * sqrtN * M
)

type Parameters struct {
	logN uint64
	qi   []uint64
	pi   []uint64
}

var testParameters = Parameters{
	//10, Qi60[len(Qi60)-1:], Pi60[len(Pi60)-1:],
	10, Qi60[len(Qi60)-1:], []uint64{8397313},
}

// Qi60 are the first [0:32] 61-bit close to 2^{62} NTT-friendly primes for N up to 2^{17}
// +1 -> prime bit += 61
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
