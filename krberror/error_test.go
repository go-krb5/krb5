package krberror

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorf(t *testing.T) {
	err := fmt.Errorf("an error")

	var a Krberror

	a = Errorf(err, "cause", "some text")
	assert.Equal(t, "[Root cause: cause] cause: some text: an error", a.Error())
	a = Errorf(err, "cause", "arg1=%d arg2=%s", 123, "arg")
	assert.Equal(t, "[Root cause: cause] cause: arg1=123 arg2=arg: an error", a.Error())

	err = NewErrorf("another error", "some text")
	a = Errorf(err, "cause", "some text")
	assert.Equal(t, "[Root cause: another error] cause: some text < another error: some text", a.Error())
	a = Errorf(err, "cause", "arg1=%d arg2=%s", 123, "arg")
	assert.Equal(t, "[Root cause: another error] cause: arg1=123 arg2=arg < another error: some text", a.Error())
}

func TestErrorfKeepsTheCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("cause")

	err := Errorf(Errorf(cause, KDCError, "inner %d", 1), NetworkingError, "outer")

	assert.ErrorIs(t, err, cause)
	assert.Equal(t, "[Root cause: KDC_Error] Networking_Error: outer < KDC_Error: inner 1: cause", err.Error())
	assert.NoError(t, errors.Unwrap(NewErrorf(KDCError, "no cause")))
}
