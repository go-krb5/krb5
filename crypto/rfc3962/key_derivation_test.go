package rfc3962

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/crypto/common"
)

func TestS2KparamsToItertions(t *testing.T) {
	t.Parallel()

	invalidLengthParams := "four"

	_, err := S2KparamsToItertions(invalidLengthParams)
	assert.Contains(t, err.Error(), "invalid s2kparams length", "Error message should mention s2kparams length")
}

func TestS2KparamsToItertionsZeroMeansTwoToThe32(t *testing.T) {
	t.Parallel()

	_, err := S2KparamsToItertions("00000000")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "4294967296")
	assert.Contains(t, err.Error(), "exceeds")
}

func TestS2KparamsToItertionsBounds(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		s2kparams  string
		iterations int64
		err        bool
	}{
		{name: "the RFC 3962 default of 4096", s2kparams: "00001000", iterations: 4096},
		{name: "the minimum expressible count", s2kparams: "00000001", iterations: 1},
		{name: "the maximum accepted count", s2kparams: common.IterationsToS2Kparams(common.MaxS2KIterations), iterations: int64(common.MaxS2KIterations)},
		{name: "one past the maximum", s2kparams: common.IterationsToS2Kparams(common.MaxS2KIterations + 1), err: true},
		{name: "not eight hex digits", s2kparams: "0000", err: true},
		{name: "not hex", s2kparams: "zzzzzzzz", err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			i, err := S2KparamsToItertions(tc.s2kparams)

			if tc.err {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.iterations, i)
		})
	}
}
