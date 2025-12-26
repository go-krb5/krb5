package rfc3962

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestS2KparamsToItertions(t *testing.T) {
	t.Parallel()

	invalidLengthParams := "four"

	_, err := S2KparamsToItertions(invalidLengthParams)
	assert.Contains(t, err.Error(), "invalid s2kparams length", "Error message should mention s2kparams length")
}
