package owchcca

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/MingLLuo/OW-ChCCA-KEM/pkg"
	"github.com/kr/pretty"
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

			// Encapsulate a shared key
			ct, ss1, err := Encapsulate(pk)
			if err != nil {
				t.Fatalf("Encapsulate failed: %v", err)
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

	skBytes, err := sk1.Bytes()
	if err != nil {
		t.Fatalf("Failed to serialize private key: %v", err)
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
	rand.Read(invalidCT)

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

func BenchmarkKEM(b *testing.B) {
	testParams := pkg.ListParameterSets()
	for _, paramName := range testParams {
		params, _ := pkg.GetParameterSet(paramName)
		pretty.Println(params)
	}
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
