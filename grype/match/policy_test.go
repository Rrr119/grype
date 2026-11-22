package match

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func policyMatch(id string, cvssScores []float64, epssScores []float64) Match {
	meta := &vulnerability.Metadata{
		ID: id,
	}
	for _, score := range cvssScores {
		meta.Cvss = append(meta.Cvss, vulnerability.Cvss{
			Source:  "nvd",
			Version: "v3.1",
			Metrics: vulnerability.CvssMetrics{BaseScore: score},
		})
	}
	for _, score := range epssScores {
		meta.EPSS = append(meta.EPSS, vulnerability.EPSS{
			CVE:  id,
			EPSS: score,
		})
	}
	return Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference:   vulnerability.Reference{ID: id},
			Metadata:    meta,
			PackageName: "some-pkg",
		},
		Package: pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "some-pkg",
			Version:  "1.0.0",
			Type:     syftPkg.DebPkg,
			Language: syftPkg.UnknownLanguage,
		},
	}
}

func TestHighestCVSSBaseScore(t *testing.T) {
	t.Run("picks highest score across sources", func(t *testing.T) {
		m := policyMatch("CVE-1", []float64{5.3, 9.1, 7.0}, nil)
		score, ok := HighestCVSSBaseScore(m)
		require.True(t, ok)
		assert.Equal(t, 9.1, score)
	})

	t.Run("ignores zero base scores", func(t *testing.T) {
		m := policyMatch("CVE-2", []float64{0, 4.4}, nil)
		score, ok := HighestCVSSBaseScore(m)
		require.True(t, ok)
		assert.Equal(t, 4.4, score)
	})

	t.Run("no metadata", func(t *testing.T) {
		m := Match{Vulnerability: vulnerability.Vulnerability{}}
		_, ok := HighestCVSSBaseScore(m)
		assert.False(t, ok)
	})

	t.Run("no usable score", func(t *testing.T) {
		m := policyMatch("CVE-3", []float64{0}, nil)
		_, ok := HighestCVSSBaseScore(m)
		assert.False(t, ok)
	})
}

func TestHighestEPSS(t *testing.T) {
	m := policyMatch("CVE-4", nil, []float64{0.001, 0.87, 0.42})
	score, ok := HighestEPSS(m)
	require.True(t, ok)
	assert.Equal(t, 0.87, score)

	empty := Match{Vulnerability: vulnerability.Vulnerability{}}
	_, ok = HighestEPSS(empty)
	assert.False(t, ok)
}

func TestPolicyThresholdsValidate(t *testing.T) {
	cases := []struct {
		name    string
		policy  PolicyThresholds
		wantErr require.ErrorAssertionFunc
	}{
		{name: "zero values are valid", policy: PolicyThresholds{}, wantErr: require.NoError},
		{name: "max cvss", policy: PolicyThresholds{MinCVSS: 10}, wantErr: require.NoError},
		{name: "max epss", policy: PolicyThresholds{MinEPSS: 1}, wantErr: require.NoError},
		{name: "cvss too high", policy: PolicyThresholds{MinCVSS: 10.1}, wantErr: require.Error},
		{name: "cvss negative", policy: PolicyThresholds{MinCVSS: -1}, wantErr: require.Error},
		{name: "epss too high", policy: PolicyThresholds{MinEPSS: 1.01}, wantErr: require.Error},
		{name: "epss negative", policy: PolicyThresholds{MinEPSS: -0.2}, wantErr: require.Error},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.wantErr(t, tc.policy.Validate())
		})
	}
}

func TestPolicyFilterIgnoreMatch(t *testing.T) {
	highRisk := policyMatch("CVE-HIGH", []float64{9.8}, []float64{0.95})
	lowRisk := policyMatch("CVE-LOW", []float64{2.1}, []float64{0.002})
	midRisk := policyMatch("CVE-MID", []float64{6.5}, []float64{0.6})
	noScores := policyMatch("CVE-NONE", nil, nil)

	t.Run("disabled filter keeps everything", func(t *testing.T) {
		f, err := NewPolicyFilter(PolicyThresholds{})
		require.NoError(t, err)
		assert.Nil(t, f.IgnoreMatch(highRisk))
		assert.Nil(t, f.IgnoreMatch(noScores))
	})

	t.Run("cvss threshold keeps missing data by default", func(t *testing.T) {
		f, err := NewPolicyFilter(PolicyThresholds{MinCVSS: 7})
		require.NoError(t, err)

		assert.Nil(t, f.IgnoreMatch(highRisk))
		assert.Nil(t, f.IgnoreMatch(noScores))

		rules := f.IgnoreMatch(lowRisk)
		require.Len(t, rules, 1)
		assert.Equal(t, PolicyReasonCVSS, rules[0].Reason[:len(PolicyReasonCVSS)])
	})

	t.Run("cvss threshold excludes missing when configured", func(t *testing.T) {
		f, err := NewPolicyFilter(PolicyThresholds{MinCVSS: 7, ExcludeMissingCVSS: true})
		require.NoError(t, err)

		rules := f.IgnoreMatch(noScores)
		require.Len(t, rules, 1)
		assert.Contains(t, rules[0].Reason, PolicyReasonCVSS)
	})

	t.Run("epss threshold", func(t *testing.T) {
		f, err := NewPolicyFilter(PolicyThresholds{MinEPSS: 0.5})
		require.NoError(t, err)

		assert.Nil(t, f.IgnoreMatch(highRisk))

		rules := f.IgnoreMatch(lowRisk)
		require.Len(t, rules, 1)
		assert.Contains(t, rules[0].Reason, PolicyReasonEPSS)
	})

	t.Run("combined thresholds record both reasons", func(t *testing.T) {
		f, err := NewPolicyFilter(PolicyThresholds{MinCVSS: 7, MinEPSS: 0.5})
		require.NoError(t, err)

		rules := f.IgnoreMatch(lowRisk)
		require.Len(t, rules, 2)
		assert.Contains(t, rules[0].Reason, PolicyReasonCVSS)
		assert.Contains(t, rules[1].Reason, PolicyReasonEPSS)

		assert.Nil(t, f.IgnoreMatch(highRisk))

		// a match meeting both thresholds (inclusive) is kept
		passing := policyMatch("CVE-PASS", []float64{7.0}, []float64{0.5})
		assert.Nil(t, f.IgnoreMatch(passing))

		// a match failing only one threshold reports just that reason
		rules = f.IgnoreMatch(midRisk)
		require.Len(t, rules, 1)
		assert.Contains(t, rules[0].Reason, PolicyReasonCVSS)
	})

	t.Run("constructor rejects invalid thresholds", func(t *testing.T) {
		_, err := NewPolicyFilter(PolicyThresholds{MinEPSS: 2})
		require.Error(t, err)
	})
}

func TestApplyPolicyFilterSplitsMatches(t *testing.T) {
	highRisk := policyMatch("CVE-HIGH", []float64{9.8}, []float64{0.95})
	lowRisk := policyMatch("CVE-LOW", []float64{2.1}, []float64{0.002})

	filter, err := NewPolicyFilter(PolicyThresholds{MinCVSS: 7})
	require.NoError(t, err)

	kept, ignored := ApplyIgnoreFilters([]Match{highRisk, lowRisk}, *filter)

	require.Len(t, kept, 1)
	assert.Equal(t, "CVE-HIGH", kept[0].Vulnerability.ID)

	require.Len(t, ignored, 1)
	assert.Equal(t, "CVE-LOW", ignored[0].Vulnerability.ID)
	require.Len(t, ignored[0].AppliedIgnoreRules, 1)
	assert.Contains(t, ignored[0].AppliedIgnoreRules[0].Reason, PolicyReasonCVSS)
}

func TestIgnoreRuleWithScoreThresholds(t *testing.T) {
	highRisk := policyMatch("CVE-HIGH", []float64{9.8}, []float64{0.95})
	lowRisk := policyMatch("CVE-LOW", []float64{2.1}, []float64{0.002})
	noScores := policyMatch("CVE-NONE", nil, nil)

	maxCVSS := 5.0
	cvssRule := IgnoreRule{MaxCVSS: &maxCVSS}
	assert.Nil(t, cvssRule.IgnoreMatch(highRisk))
	require.Len(t, cvssRule.IgnoreMatch(lowRisk), 1)
	// missing data counts as score 0 and is therefore below the threshold
	require.Len(t, cvssRule.IgnoreMatch(noScores), 1)

	maxEPSS := 0.5
	epssRule := IgnoreRule{MaxEPSS: &maxEPSS}
	assert.Nil(t, epssRule.IgnoreMatch(highRisk))
	require.Len(t, epssRule.IgnoreMatch(lowRisk), 1)

	t.Run("threshold composes with other criteria", func(t *testing.T) {
		rule := IgnoreRule{
			Namespace: "nvd:cpe",
			MaxCVSS:   &maxCVSS,
		}
		withNamespace := lowRisk
		withNamespace.Vulnerability.Namespace = "nvd:cpe"
		require.Len(t, rule.IgnoreMatch(withNamespace), 1)

		wrongNamespace := lowRisk
		wrongNamespace.Vulnerability.Namespace = "other"
		assert.Nil(t, rule.IgnoreMatch(wrongNamespace))
	})
}
