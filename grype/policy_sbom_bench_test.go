package grype_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/match"
	matcherMock "github.com/anchore/grype/grype/matcher/mock"
	"github.com/anchore/grype/grype/pkg"
	jsonpresenter "github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	vulnMock "github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// This benchmark-style test drives the full VulnerabilityMatcher pipeline
// (matching -> ignore rules -> CVSS/EPSS risk policy -> JSON presentation)
// over 100 synthetic SBOMs and compares the unfiltered baseline against the
// policy-filtered runs. It is fully offline and deterministic: the mock
// matcher emits a fixed set of findings per package, so the numbers below are
// reproducible without a vulnerability database or network access.

const sbomCount = 100

// packagesPerSBOM keeps the runtime small while still producing a large,
// varied finding set across the 100 SBOMs.
const packagesPerSBOM = 20

type syntheticFinding struct {
	cvss float64
	epss float64
}

// findingProfile cycles through a fixed risk profile so every SBOM gets the
// same, deterministic distribution of CVSS/EPSS scores.
var findingProfile = []syntheticFinding{
	{cvss: 9.8, epss: 0.95}, // critical, actively exploited
	{cvss: 8.1, epss: 0.40}, // high
	{cvss: 7.5, epss: 0.05}, // high but unlikely to be exploited
	{cvss: 6.4, epss: 0.60}, // medium with notable EPSS
	{cvss: 5.3, epss: 0.02}, // medium
	{cvss: 3.9, epss: 0.01}, // low
	{cvss: 2.0, epss: 0.001},
	{cvss: 0, epss: 0}, // no score data at all
}

type sbomScanResult struct {
	Name           string
	TotalMatches   int
	KeptMatches    int
	IgnoredMatches int
}

func generateSyntheticSBOM(t *testing.T, index int) []pkg.Package {
	t.Helper()
	packages := make([]pkg.Package, 0, packagesPerSBOM)
	for packageIndex := 0; packageIndex < packagesPerSBOM; packageIndex++ {
		packages = append(packages, pkg.Package{
			ID:        pkg.ID(uuid.NewString()),
			Name:      fmt.Sprintf("sbom%d-pkg%d", index, packageIndex),
			Version:   fmt.Sprintf("1.%d.0", packageIndex),
			Type:      syftPkg.DebPkg,
			Locations: file.NewLocationSet(file.NewLocation(fmt.Sprintf("/usr/lib/sbom%d/pkg%d", index, packageIndex))),
		})
	}
	return packages
}

// newSyntheticMatcher returns a matcher that turns every package into one
// finding per entry in findingProfile, attaching CVSS and EPSS metadata.
func newSyntheticMatcher() match.Matcher {
	return matcherMock.New(syftPkg.DebPkg, func(_ vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
		matches := make([]match.Match, 0, len(findingProfile))
		for index, finding := range findingProfile {
			meta := &vulnerability.Metadata{
				ID:        fmt.Sprintf("CVE-SYN-%d", index),
				Namespace: "nvd:cpe",
				Severity:  "high",
			}
			if finding.cvss > 0 {
				meta.Cvss = []vulnerability.Cvss{{
					Source:  "nvd",
					Version: "v3.1",
					Metrics: vulnerability.CvssMetrics{BaseScore: finding.cvss},
				}}
			}
			if finding.epss > 0 {
				meta.EPSS = []vulnerability.EPSS{{
					CVE:  fmt.Sprintf("CVE-SYN-%d", index),
					EPSS: finding.epss,
				}}
			}
			matches = append(matches, match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        fmt.Sprintf("%s-CVE-SYN-%d", p.Name, index),
						Namespace: "nvd:cpe",
					},
					PackageName: p.Name,
					Metadata:    meta,
				},
				Package: p,
			})
		}
		return matches, nil, nil
	})
}

func runSBOMScan(t *testing.T, packages []pkg.Package, policy *match.PolicyFilter, ignoreRules []match.IgnoreRule) (match.Matches, []match.IgnoredMatch) {
	t.Helper()
	matcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnMock.VulnerabilityProvider(),
		Matchers:              []match.Matcher{newSyntheticMatcher()},
		IgnoreRules:           ignoreRules,
		Policy:                policy,
	}

	remaining, ignored, err := matcher.FindMatches(packages, pkg.Context{})
	require.NoError(t, err)
	return *remaining, ignored
}

// policyComparison is the JSON-serializable comparison report for one policy
// across all 100 SBOMs.
type policyComparison struct {
	Policy          string           `json:"policy"`
	SBOMCount       int              `json:"sbomCount"`
	TotalFindings   int              `json:"totalFindings"`
	KeptFindings    int              `json:"keptFindings"`
	IgnoredFindings int              `json:"ignoredFindings"`
	SuppressionRate float64          `json:"suppressionRate"`
	PerSBOM         []sbomScanResult `json:"perSbom"`
}

func buildComparison(t *testing.T, name string, policy *match.PolicyFilter, ignoreRules []match.IgnoreRule, allSBOMs [][]pkg.Package) policyComparison {
	t.Helper()
	report := policyComparison{
		Policy:    name,
		SBOMCount: len(allSBOMs),
		PerSBOM:   make([]sbomScanResult, 0, len(allSBOMs)),
	}

	for index, packages := range allSBOMs {
		remaining, ignored := runSBOMScan(t, packages, policy, ignoreRules)
		total := remaining.Count() + len(ignored)
		report.TotalFindings += total
		report.KeptFindings += remaining.Count()
		report.IgnoredFindings += len(ignored)
		report.PerSBOM = append(report.PerSBOM, sbomScanResult{
			Name:           fmt.Sprintf("sbom-%03d", index),
			TotalMatches:   total,
			KeptMatches:    remaining.Count(),
			IgnoredMatches: len(ignored),
		})
	}

	if report.TotalFindings > 0 {
		report.SuppressionRate = float64(report.IgnoredFindings) / float64(report.TotalFindings)
	}
	return report
}

func mustPolicyFilter(t *testing.T, thresholds match.PolicyThresholds) *match.PolicyFilter {
	t.Helper()
	filter, err := match.NewPolicyFilter(thresholds)
	require.NoError(t, err)
	return filter
}

// build100SBOMComparisons runs every policy variant across the 100 SBOMs and
// returns the ordered comparison reports, starting with the no-policy baseline.
func build100SBOMComparisons(t *testing.T, allSBOMs [][]pkg.Package) []policyComparison {
	t.Helper()

	cvssOnly := mustPolicyFilter(t, match.PolicyThresholds{MinCVSS: 7})
	epssOnly := mustPolicyFilter(t, match.PolicyThresholds{MinEPSS: 0.1})
	combined := mustPolicyFilter(t, match.PolicyThresholds{MinCVSS: 7, MinEPSS: 0.1})
	strict := mustPolicyFilter(t, match.PolicyThresholds{
		MinCVSS: 7, MinEPSS: 0.1,
		ExcludeMissingCVSS: true,
		ExcludeMissingEPSS: true,
	})

	lowCVSSThreshold := 4.0
	ignoreRules := []match.IgnoreRule{{MaxCVSS: &lowCVSSThreshold}}

	return []policyComparison{
		buildComparison(t, "no-policy", nil, nil, allSBOMs),
		buildComparison(t, "min-cvss-7", cvssOnly, nil, allSBOMs),
		buildComparison(t, "min-epss-0.1", epssOnly, nil, allSBOMs),
		buildComparison(t, "min-cvss-7-and-epss-0.1", combined, nil, allSBOMs),
		buildComparison(t, "strict-exclude-missing", strict, nil, allSBOMs),
		buildComparison(t, "ignore-rule-max-cvss-4", nil, ignoreRules, allSBOMs),
	}
}

func TestPolicyFilterAcross100SBOMs(t *testing.T) {
	allSBOMs := make([][]pkg.Package, sbomCount)
	for index := range allSBOMs {
		allSBOMs[index] = generateSyntheticSBOM(t, index)
	}

	expectedFindingsPerSBOM := packagesPerSBOM * len(findingProfile)

	comparisons := build100SBOMComparisons(t, allSBOMs)
	baseline := comparisons[0]

	t.Run("baseline counts every finding", func(t *testing.T) {
		assert.Equal(t, sbomCount, baseline.SBOMCount)
		assert.Equal(t, sbomCount*expectedFindingsPerSBOM, baseline.TotalFindings)
		assert.Equal(t, baseline.TotalFindings, baseline.KeptFindings)
		assert.Zero(t, baseline.IgnoredFindings)
		assert.Len(t, baseline.PerSBOM, sbomCount)
	})

	t.Run("every policy suppresses a non-empty subset without losing findings", func(t *testing.T) {
		for _, report := range comparisons[1:] {
			assert.Equal(t, baseline.TotalFindings, report.TotalFindings,
				"policy %q must preserve every finding (kept + ignored)", report.Policy)
			assert.Equal(t, baseline.TotalFindings, report.KeptFindings+report.IgnoredFindings)
			assert.Greater(t, report.IgnoredFindings, 0)
			assert.Less(t, report.KeptFindings, baseline.KeptFindings)
		}
	})

	t.Run("expected suppression counts match the fixed profile", func(t *testing.T) {
		// per package, the 8-entry profile failing each rule:
		// CVSS < 7: the low-score entries 6.4/5.3/3.9/2.0 -> 4 entries; the no-data entry is kept by default
		// EPSS < 0.1: 0.05/0.02/0.01/0.001 -> 4 entries; the no-data entry is kept by default
		// combined default (union, sharing the no-data entry) -> 5 entries
		// strict also suppresses the no-data entry            -> 6 entries
		// max-cvss 4 ignore rule (missing and zero both count as score 0) -> 3 entries
		cvssReport := comparisons[1]
		assert.Equal(t, sbomCount*packagesPerSBOM*4, cvssReport.IgnoredFindings)

		epssReport := comparisons[2]
		assert.Equal(t, sbomCount*packagesPerSBOM*4, epssReport.IgnoredFindings)

		combinedReport := comparisons[3]
		assert.Equal(t, sbomCount*packagesPerSBOM*5, combinedReport.IgnoredFindings)

		strictReport := comparisons[4]
		assert.Equal(t, sbomCount*packagesPerSBOM*6, strictReport.IgnoredFindings)

		ignoreRuleReport := comparisons[5]
		assert.Equal(t, sbomCount*packagesPerSBOM*3, ignoreRuleReport.IgnoredFindings)
	})

	t.Run("per-SBOM results are uniform", func(t *testing.T) {
		for _, report := range comparisons {
			for _, perSBOM := range report.PerSBOM {
				assert.Equal(t, expectedFindingsPerSBOM, perSBOM.TotalMatches)
			}
		}
	})

	t.Run("comparison report is JSON serializable", func(t *testing.T) {
		payload, err := json.MarshalIndent(comparisons, "", "  ")
		require.NoError(t, err)
		assert.NotEmpty(t, payload)
		var decoded []policyComparison
		require.NoError(t, json.Unmarshal(payload, &decoded))
		assert.Len(t, decoded, len(comparisons))
	})
}

func TestPolicyFilteredScanProducesJSONDocument(t *testing.T) {
	packages := generateSyntheticSBOM(t, 0)
	cvssFilter, err := match.NewPolicyFilter(match.PolicyThresholds{MinCVSS: 7})
	require.NoError(t, err)

	remaining, ignored := runSBOMScan(t, packages, cvssFilter, nil)

	document, err := models.NewDocument(
		clio.Identification{Name: "grype-policy-test", Version: "test"},
		packages,
		pkg.Context{},
		remaining,
		ignored,
		nil,
		nil,
		nil,
		models.SortByPackage,
		false,
		nil,
	)
	require.NoError(t, err)

	var buffer bytes.Buffer
	require.NoError(t, jsonpresenter.NewPresenter(models.PresenterConfig{Document: document, Pretty: true}).Present(&buffer))

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(buffer.Bytes(), &decoded))

	ignoredMatches, ok := decoded["ignoredMatches"].([]any)
	require.True(t, ok)
	assert.Len(t, ignoredMatches, len(ignored))

	for _, entry := range ignoredMatches {
		ignoredMatch := entry.(map[string]any)
		rules, ok := ignoredMatch["appliedIgnoreRules"].([]any)
		require.True(t, ok)
		require.NotEmpty(t, rules)
		reason := rules[0].(map[string]any)["reason"].(string)
		assert.Contains(t, reason, match.PolicyReasonCVSS)
	}
}
