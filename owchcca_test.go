package owchcca

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/MingLLuo/OW-ChCCA-KEM/pkg"
)

func TestKEMConsistency(t *testing.T) {
	// Test with all parameter sets
	testParams := pkg.ListParameterSets()

	for _, paramName := range testParams {
		params, err := pkg.GetParameterSet(paramName)
		if err != nil {
			t.Fatalf("GetParameterSet failed: %v", err)
		}
		t.Run(params.Name, func(t *testing.T) {
			// Generate a key pair
			pk, sk, err := GenerateKeyPair(params)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}
			if got, want := len(mustBytes(t, pk)), params.KeyParams.PublicKeySize; got != want {
				t.Fatalf("public key serialized size mismatch: got=%d want=%d", got, want)
			}
			if got, want := len(mustBytes(t, sk)), params.KeyParams.PrivateKeySize; got != want {
				t.Fatalf("private key serialized size mismatch: got=%d want=%d", got, want)
			}

			// Encapsulate a shared key
			ct, ss1, err := Encapsulate(pk)
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
			}
			if got, want := len(ct), params.KeyParams.CiphertextSize; got != want {
				t.Fatalf("ciphertext size mismatch: got=%d want=%d", got, want)
			}
			if got, want := len(ss1), params.KeyParams.SharedKeySize; got != want {
				t.Fatalf("shared key size mismatch: got=%d want=%d", got, want)
			}

			// Decapsulate the shared key
			ss2, err := Decapsulate(sk, ct)
			if err != nil {
				t.Fatalf("Decapsulate failed: %v", err)
			}

			// Verify that the shared keys match
			if !bytes.Equal(ss1, ss2) {
				t.Errorf("Shared keys do not match")
			}
		})
	}
}

func TestKEMSerialization(t *testing.T) {
	// Use the lowest parameter set for simplicity
	params := pkg.GetDefaultParameterSet()

	// Generate a key pair
	pk1, sk1, err := GenerateKeyPair(params)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Serialize the keys
	pkBytes, err := pk1.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize public key: %v", err)
	}
	if got, want := len(pkBytes), params.KeyParams.PublicKeySize; got != want {
		t.Fatalf("public key serialized size mismatch: got=%d want=%d", got, want)
	}

	skBytes, err := sk1.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize private key: %v", err)
	}
	if got, want := len(skBytes), params.KeyParams.PrivateKeySize; got != want {
		t.Fatalf("private key serialized size mismatch: got=%d want=%d", got, want)
	}

	// Parse the keys
	pk2, err := ParsePublicKey(pkBytes, &params)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}

	sk2, err := ParsePrivateKey(skBytes, pk2)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// Verify that the keys are equal
	if !pk1.Equal(pk2) {
		t.Errorf("Public keys do not match after serialization")
	}

	if !sk1.Equal(sk2) {
		t.Errorf("Private keys do not match after serialization")
	}

	// Test encapsulation/decapsulation with the parsed keys
	ct, ss1, err := Encapsulate(pk2)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}
	if got, want := len(ct), params.KeyParams.CiphertextSize; got != want {
		t.Fatalf("ciphertext size mismatch: got=%d want=%d", got, want)
	}
	if got, want := len(ss1), params.KeyParams.SharedKeySize; got != want {
		t.Fatalf("shared key size mismatch: got=%d want=%d", got, want)
	}

	ss2, err := Decapsulate(sk2, ct)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(ss1, ss2) {
		t.Errorf("Shared keys do not match after serialization")
	}
}

func TestInvalidInputs(t *testing.T) {
	// Use the lowest parameter set for simplicity
	params := pkg.GetDefaultParameterSet()

	// Generate a key pair
	pk, sk, err := GenerateKeyPair(params)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Create an invalid ciphertext
	invalidCT := make([]byte, params.KeyParams.CiphertextSize+1)
	if _, err := rand.Read(invalidCT); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	// Try to decapsulate with an invalid ciphertext
	_, err = Decapsulate(sk, invalidCT)
	if err == nil {
		t.Errorf("Decapsulate should fail with an invalid ciphertext")
	}

	// Generate a valid ciphertext
	ct, _, err := Encapsulate(pk)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	// Modify the ciphertext
	modifiedCT := make([]byte, len(ct))
	copy(modifiedCT, ct)
	modifiedCT[0] ^= 0xFF

	// Try to decapsulate with a modified ciphertext
	_, err = Decapsulate(sk, modifiedCT)
	if err == nil {
		t.Errorf("Decapsulate should fail with a modified ciphertext")
	}
}

func TestNilAndTruncatedInputs(t *testing.T) {
	params := pkg.GetDefaultParameterSet()
	pk, sk, err := GenerateKeyPair(params)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if _, _, err := Encapsulate(nil); !errors.Is(err, pkg.ErrInvalidPublicKey) {
		t.Fatalf("Encapsulate(nil) error mismatch: %v", err)
	}

	if _, err := Decapsulate(nil, nil); !errors.Is(err, pkg.ErrInvalidPrivateKey) {
		t.Fatalf("Decapsulate(nil) error mismatch: %v", err)
	}

	if _, err := ParsePublicKey([]byte{1, 2, 3}, nil); !errors.Is(err, pkg.ErrParameterValidation) {
		t.Fatalf("ParsePublicKey nil params error mismatch: %v", err)
	}

	if _, err := ParsePrivateKey([]byte{1, 2, 3}, nil); !errors.Is(err, pkg.ErrInvalidPublicKey) {
		t.Fatalf("ParsePrivateKey nil pk error mismatch: %v", err)
	}

	pkBytes := mustBytes(t, pk)
	if _, err := ParsePublicKey(pkBytes[:len(pkBytes)-1], &params); err == nil {
		t.Fatalf("ParsePublicKey should reject truncated input")
	}

	skBytes := mustBytes(t, sk)
	if _, err := ParsePrivateKey(skBytes[:len(skBytes)-1], pk); err == nil {
		t.Fatalf("ParsePrivateKey should reject truncated input")
	}
}

func BenchmarkKEM(b *testing.B) {
	testParams := pkg.ListParameterSets()
	for _, paramName := range testParams {
		params, err := pkg.GetParameterSet(paramName)
		if err != nil {
			b.Fatalf("GetParameterSet failed: %v", err)
		}
		b.Logf("Benchmarking parameter set %s", params.Name)
		// Generate a key pair outside the benchmark loop
		pk, sk, err := GenerateKeyPair(params)
		if err != nil {
			b.Fatalf("GenerateKeyPair failed: %v", err)
		}

		b.Run("KeyGen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := GenerateKeyPair(params)
				if err != nil {
					b.Fatalf("GenerateKeyPair failed: %v", err)
				}
			}
		})

		b.Run("Encap", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, err := Encapsulate(pk)
				if err != nil {
					b.Fatalf("Encapsulate failed: %v", err)
				}
			}
		})

		// Generate a ciphertext for Decaps benchmarks
		ct, _, err := Encapsulate(pk)
		if err != nil {
			b.Fatalf("Encapsulate failed: %v", err)
		}

		b.Run("Decap", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := Decapsulate(sk, ct)
				if err != nil {
					b.Fatalf("Decapsulate failed: %v", err)
				}
			}
		})
	}
}

func mustBytes(t *testing.T, v interface{ Bytes() ([]byte, error) }) []byte {
	t.Helper()
	b, err := v.Bytes()
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}
	return b
}
