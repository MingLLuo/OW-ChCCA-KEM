//go:build highparams

package pkg

import "testing"

func TestCalculateParametersHighLevelDemo(t *testing.T) {
	param := CalculateParameters(Security128)
	if err := param.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	t.Logf("high-parameter demo: name=%s n=%d m=%d qBits=%d", param.Name, param.LatticeParams.N, param.LatticeParams.M, param.LatticeParams.Q.BitLen())
}
