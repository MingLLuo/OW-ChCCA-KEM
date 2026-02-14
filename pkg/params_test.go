package pkg

import (
	"strconv"
	"testing"
)

func TestCalculateParametersDefaultLevels(t *testing.T) {
	levels := []SecurityLevel{Security16, Security32, Security64}
	for _, level := range levels {
		level := level
		t.Run("level-"+strconv.Itoa(int(level)), func(t *testing.T) {
			param := CalculateParameters(level)
			if err := param.Validate(); err != nil {
				t.Fatalf("Validate failed: %v", err)
			}
			if param.KeyParams.PublicKeySize <= 0 || param.KeyParams.PrivateKeySize <= 0 || param.KeyParams.CiphertextSize <= 0 {
				t.Fatalf("invalid key sizes: %+v", param.KeyParams)
			}
		})
	}
}
