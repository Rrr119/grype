package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSortByPostLoadNormalizesEPSS(t *testing.T) {
	o := defaultSortBy()
	o.Criteria = "EPSS"

	require.NoError(t, o.PostLoad())
	assert.Equal(t, "epss", o.Criteria)
}

func TestSortByPostLoadRejectsUnknownCriteria(t *testing.T) {
	o := defaultSortBy()
	o.Criteria = "not-a-strategy"

	require.Error(t, o.PostLoad())
}
