package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetJanitorIntervalShouldFloorANonPositiveInterval(t *testing.T) {
	janitorInterval.Store(0)

	assert.Equal(t, defaultJanitorInterval, setJanitorInterval(0),
		"a zero interval would sweep continuously and retire every entry the moment it was recorded")

	janitorInterval.Store(0)

	assert.Equal(t, defaultJanitorInterval, setJanitorInterval(-time.Second))
}

func TestSetJanitorIntervalShouldKeepTheLongestIntervalAsked(t *testing.T) {
	janitorInterval.Store(0)

	require.Equal(t, 5*time.Minute, setJanitorInterval(5*time.Minute))
	assert.Equal(t, 10*time.Minute, setJanitorInterval(10*time.Minute),
		"a service with a wider clock skew must widen the age entries are kept for")
	assert.Equal(t, 10*time.Minute, setJanitorInterval(time.Minute),
		"a service with a narrower skew must not shorten it: an entry has to outlive the skew of every service sharing the cache")
}

func TestGetReplayCacheShouldNeverLeaveTheJanitorWithANonPositiveInterval(t *testing.T) {
	janitorInterval.Store(0)

	require.NotNil(t, GetReplayCache(0))
	assert.Positive(t, janitorInterval.Load())
}
