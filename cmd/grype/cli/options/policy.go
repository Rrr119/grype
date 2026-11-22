package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/match"
)

// policyConfig exposes the CVSS/EPSS risk-based filtering policy via the
// application config and command line flags.
type policyConfig struct {
	MinCVSS            float64 `yaml:"min-cvss" json:"min-cvss" mapstructure:"min-cvss"`
	MinEPSS            float64 `yaml:"min-epss" json:"min-epss" mapstructure:"min-epss"`
	ExcludeMissingCVSS bool    `yaml:"exclude-missing-cvss" json:"exclude-missing-cvss" mapstructure:"exclude-missing-cvss"`
	ExcludeMissingEPSS bool    `yaml:"exclude-missing-epss" json:"exclude-missing-epss" mapstructure:"exclude-missing-epss"`
}

var _ interface {
	clio.FieldDescriber
	clio.PostLoader
} = (*policyConfig)(nil)

func defaultPolicyConfig() policyConfig {
	return policyConfig{}
}

// PostLoad validates the configured threshold ranges.
func (p policyConfig) PostLoad() error {
	thresholds := p.toThresholds()
	if err := thresholds.Validate(); err != nil {
		return fmt.Errorf("invalid policy config: %w", err)
	}
	return nil
}

// toThresholds maps the CLI config onto the core match policy type.
func (p policyConfig) toThresholds() match.PolicyThresholds {
	return match.PolicyThresholds{
		MinCVSS:            p.MinCVSS,
		MinEPSS:            p.MinEPSS,
		ExcludeMissingCVSS: p.ExcludeMissingCVSS,
		ExcludeMissingEPSS: p.ExcludeMissingEPSS,
	}
}

// NewPolicyFilter builds the core policy filter, or returns nil when no
// thresholds are configured.
func (p policyConfig) NewPolicyFilter() (*match.PolicyFilter, error) {
	thresholds := p.toThresholds()
	if !thresholds.Enabled() {
		return nil, nil
	}
	return match.NewPolicyFilter(thresholds)
}

func (p policyConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&p.MinCVSS, `minimum CVSS base score (0-10) a match must have to be reported; matches below the threshold are moved to ignoredMatches`)
	descriptions.Add(&p.MinEPSS, `minimum EPSS exploitation probability (0-1) a match must have to be reported; matches below the threshold are moved to ignoredMatches`)
	descriptions.Add(&p.ExcludeMissingCVSS, `also ignore matches with no CVSS base score when min-cvss is set (default: keep matches lacking CVSS data)`)
	descriptions.Add(&p.ExcludeMissingEPSS, `also ignore matches with no EPSS data when min-epss is set (default: keep matches lacking EPSS data)`)
}
