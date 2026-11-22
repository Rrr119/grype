package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPolicyFilterFlags validates that the risk-policy flags are registered and
// that out-of-range thresholds fail before any scanning starts. These cases do
// not require a vulnerability database.
func TestPolicyFilterFlags(t *testing.T) {
	t.Run("help lists the policy flags", func(t *testing.T) {
		cmd := getGrypeCommand(t, "--help")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err)
		helpText := string(output)
		assert.Contains(t, helpText, "--min-cvss")
		assert.Contains(t, helpText, "--min-epss")
		assert.Contains(t, helpText, "--exclude-missing-cvss")
		assert.Contains(t, helpText, "--exclude-missing-epss")
	})

	cases := []struct {
		name string
		args []string
		err  string
	}{
		{
			name: "cvss above range",
			args: []string{"--min-cvss", "11"},
			err:  "policy min-cvss must be between 0 and 10",
		},
		{
			name: "epss above range",
			args: []string{"--min-epss", "1.5"},
			err:  "policy min-epss must be between 0 and 1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := make([]string, 0, len(tc.args)+1)
			args = append(args, tc.args...)
			args = append(args, "sbom:./testdata/sbom-grype-source.json")
			cmd := getGrypeCommand(t, args...)
			output, err := cmd.CombinedOutput()
			require.Error(t, err)
			assert.Contains(t, string(output), tc.err)
		})
	}
}

// TestPolicyFilterJSONOutput runs a real SBOM scan with a CVSS threshold and
// verifies that suppressed findings move into ignoredMatches with a policy
// reason in the JSON document.
func TestPolicyFilterJSONOutput(t *testing.T) {
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)

	sbomPath := filepath.Join(workingDirectory, "testdata", "sbom-grype-source.json")

	baselineFile := filepath.Join(t.TempDir(), "baseline.json")
	filteredFile := filepath.Join(t.TempDir(), "filtered.json")

	baseline := getGrypeCommand(t, "sbom:"+sbomPath, "-o", "json", "--file", baselineFile)
	assertCommandExecutionSuccess(t, baseline)

	filtered := getGrypeCommand(t, "sbom:"+sbomPath, "--min-cvss", "7", "-o", "json", "--file", filteredFile)
	assertCommandExecutionSuccess(t, filtered)

	baselineDoc := readJSONDocument(t, baselineFile)
	filteredDoc := readJSONDocument(t, filteredFile)

	baselineMatches := len(asSlice(baselineDoc["matches"]))
	filteredMatches := len(asSlice(filteredDoc["matches"]))
	ignoredMatches := asSlice(filteredDoc["ignoredMatches"])

	require.Greater(t, baselineMatches, 0)
	assert.Less(t, filteredMatches, baselineMatches)
	require.NotEmpty(t, ignoredMatches)

	// no finding is lost: kept plus ignored must equal the baseline total
	assert.Equal(t, baselineMatches, filteredMatches+len(ignoredMatches))

	for _, entry := range ignoredMatches {
		ignoredMatch := entry.(map[string]any)
		rules := asSlice(ignoredMatch["appliedIgnoreRules"])
		require.NotEmpty(t, rules)
		reason := rules[0].(map[string]any)["reason"].(string)
		assert.True(t,
			strings.Contains(reason, "policy-cvss-threshold"),
			"expected policy reason, got %q", reason)
	}
}

func readJSONDocument(t *testing.T, path string) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(path)
	require.NoError(t, err)

	var document map[string]any
	require.NoError(t, json.Unmarshal(payload, &document))
	return document
}

func asSlice(value any) []any {
	if value == nil {
		return nil
	}
	slice, _ := value.([]any)
	return slice
}
