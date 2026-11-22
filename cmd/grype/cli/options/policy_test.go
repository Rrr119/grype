package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyConfigPostLoad(t *testing.T) {
	cases := []struct {
		name    string
		cfg     policyConfig
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "empty config is valid",
			cfg:     policyConfig{},
			wantErr: require.NoError,
		},
		{
			name:    "valid thresholds",
			cfg:     policyConfig{MinCVSS: 7.5, MinEPSS: 0.1},
			wantErr: require.NoError,
		},
		{
			name:    "cvss above range",
			cfg:     policyConfig{MinCVSS: 11},
			wantErr: require.Error,
		},
		{
			name:    "epss above range",
			cfg:     policyConfig{MinEPSS: 1.5},
			wantErr: require.Error,
		},
		{
			name:    "negative cvss",
			cfg:     policyConfig{MinCVSS: -0.1},
			wantErr: require.Error,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.wantErr(t, tc.cfg.PostLoad())
		})
	}
}

func TestPolicyConfigNewPolicyFilter(t *testing.T) {
	t.Run("no thresholds returns nil", func(t *testing.T) {
		filter, err := policyConfig{}.NewPolicyFilter()
		require.NoError(t, err)
		assert.Nil(t, filter)
	})

	t.Run("thresholds build a filter", func(t *testing.T) {
		filter, err := policyConfig{MinCVSS: 7, MinEPSS: 0.2, ExcludeMissingCVSS: true}.NewPolicyFilter()
		require.NoError(t, err)
		require.NotNil(t, filter)
		assert.Equal(t, 7.0, filter.Policy.MinCVSS)
		assert.Equal(t, 0.2, filter.Policy.MinEPSS)
		assert.True(t, filter.Policy.ExcludeMissingCVSS)
	})

	t.Run("invalid thresholds fail", func(t *testing.T) {
		_, err := policyConfig{MinEPSS: 2}.NewPolicyFilter()
		require.Error(t, err)
	})
}
