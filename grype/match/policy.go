package match

import (
	"fmt"
)

// PolicyReasonCVSS is recorded on the synthetic IgnoreRule generated when a
// match is filtered out by a CVSS score threshold.
const PolicyReasonCVSS = "policy-cvss-threshold"

// PolicyReasonEPSS is recorded on the synthetic IgnoreRule generated when a
// match is filtered out by an EPSS score threshold.
const PolicyReasonEPSS = "policy-epss-threshold"

// PolicyThresholds defines risk-based filtering policy. A match is kept only
// when its CVSS base score and its EPSS score meet the configured thresholds.
// A zero threshold disables the corresponding check.
type PolicyThresholds struct {
	// MinCVSS keeps matches whose highest CVSS v2/v3/v4 base score is at or
	// above this value (0-10). Zero disables CVSS filtering.
	MinCVSS float64 `yaml:"min-cvss" json:"min-cvss" mapstructure:"min-cvss"`

	// MinEPSS keeps matches whose highest EPSS probability is at or above this
	// value (0-1). Zero disables EPSS filtering.
	MinEPSS float64 `yaml:"min-epss" json:"min-epss" mapstructure:"min-epss"`

	// ExcludeMissingCVSS ignores matches that carry no usable CVSS base score
	// when MinCVSS is set. By default such matches are kept so that a lack of
	// CVSS data never silently hides a finding.
	ExcludeMissingCVSS bool `yaml:"exclude-missing-cvss" json:"exclude-missing-cvss" mapstructure:"exclude-missing-cvss"`

	// ExcludeMissingEPSS ignores matches that carry no EPSS data when MinEPSS
	// is set. By default such matches are kept so that a lack of EPSS data
	// never silently hides a finding.
	ExcludeMissingEPSS bool `yaml:"exclude-missing-epss" json:"exclude-missing-epss" mapstructure:"exclude-missing-epss"`
}

// Enabled reports whether any threshold-based filtering is configured.
func (p PolicyThresholds) Enabled() bool {
	return p.MinCVSS > 0 || p.MinEPSS > 0
}

// Validate checks that the thresholds fall within their documented ranges.
func (p PolicyThresholds) Validate() error {
	if p.MinCVSS < 0 || p.MinCVSS > 10 {
		return fmt.Errorf("policy min-cvss must be between 0 and 10, got %v", p.MinCVSS)
	}
	if p.MinEPSS < 0 || p.MinEPSS > 1 {
		return fmt.Errorf("policy min-epss must be between 0 and 1, got %v", p.MinEPSS)
	}
	return nil
}

var _ IgnoreFilter = (*PolicyFilter)(nil)

// PolicyFilter applies risk-based PolicyThresholds to matches, returning a
// synthetic IgnoreRule for every threshold a match fails. Matches without the
// relevant score data are only filtered when the corresponding
// ExcludeMissing* option is set.
type PolicyFilter struct {
	Policy PolicyThresholds
}

// NewPolicyFilter validates the thresholds and returns a filter ready to apply.
func NewPolicyFilter(policy PolicyThresholds) (*PolicyFilter, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &PolicyFilter{Policy: policy}, nil
}

// IgnoreMatch implements IgnoreFilter. A match with no failing thresholds
// returns nil; otherwise it returns one IgnoreRule per failed threshold so the
// JSON report records every reason the match was suppressed.
func (f PolicyFilter) IgnoreMatch(m Match) []IgnoreRule {
	if !f.Policy.Enabled() {
		return nil
	}

	var rules []IgnoreRule

	if f.Policy.MinCVSS > 0 {
		score, hasCVSS := HighestCVSSBaseScore(m)
		switch {
		case !hasCVSS && f.Policy.ExcludeMissingCVSS:
			rules = append(rules, newPolicyRule(PolicyReasonCVSS,
				fmt.Sprintf("match has no CVSS base score and exclude-missing-cvss is set (threshold %.1f)", f.Policy.MinCVSS)))
		case hasCVSS && score < f.Policy.MinCVSS:
			rules = append(rules, newPolicyRule(PolicyReasonCVSS,
				fmt.Sprintf("CVSS base score %.1f is below minimum %.1f", score, f.Policy.MinCVSS)))
		}
	}

	if f.Policy.MinEPSS > 0 {
		score, hasEPSS := HighestEPSS(m)
		switch {
		case !hasEPSS && f.Policy.ExcludeMissingEPSS:
			rules = append(rules, newPolicyRule(PolicyReasonEPSS,
				fmt.Sprintf("match has no EPSS score and exclude-missing-epss is set (threshold %.4f)", f.Policy.MinEPSS)))
		case hasEPSS && score < f.Policy.MinEPSS:
			rules = append(rules, newPolicyRule(PolicyReasonEPSS,
				fmt.Sprintf("EPSS score %.4f is below minimum %.4f", score, f.Policy.MinEPSS)))
		}
	}

	return rules
}

func newPolicyRule(reason, detail string) IgnoreRule {
	return IgnoreRule{
		Reason: reason + ": " + detail,
	}
}

// HighestCVSSBaseScore returns the largest CVSS base score attached to the
// match's vulnerability metadata across all sources. The boolean is false when
// the match has no usable base score.
func HighestCVSSBaseScore(m Match) (float64, bool) {
	meta := m.Vulnerability.Metadata
	if meta == nil {
		return 0, false
	}

	var highest float64
	found := false
	for _, c := range meta.Cvss {
		if c.Metrics.BaseScore <= 0 {
			continue
		}
		if !found || c.Metrics.BaseScore > highest {
			highest = c.Metrics.BaseScore
			found = true
		}
	}
	return highest, found
}

// HighestEPSS returns the largest EPSS exploitation probability attached to
// the match's vulnerability metadata. The boolean is false when the match has
// no EPSS data.
func HighestEPSS(m Match) (float64, bool) {
	meta := m.Vulnerability.Metadata
	if meta == nil {
		return 0, false
	}

	var highest float64
	found := false
	for _, e := range meta.EPSS {
		if !found || e.EPSS > highest {
			highest = e.EPSS
			found = true
		}
	}
	return highest, found
}
