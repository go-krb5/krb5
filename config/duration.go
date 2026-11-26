package config

import (
	"errors"
	"math"
	"time"
)

var errInvalidDuration = errors.New("invalid time duration")

const (
	deltatMaxTime = math.MaxInt32
	deltatMinTime = math.MinInt32
	deltatDay     = 24 * 3600
	deltatHour    = 3600
)

func parseDuration(s string) (time.Duration, error) {
	p := &deltatParser{s: s}

	v, err := p.deltat()
	if err != nil {
		return 0, err
	}

	if p.i != len(p.s) {
		return 0, errInvalidDuration
	}

	return time.Duration(v) * time.Second, nil
}

type deltatParser struct {
	s string
	i int
}

func (p *deltatParser) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}

	return 0
}

func (p *deltatParser) ws() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n') {
		p.i++
	}
}

func (p *deltatParser) digits() (int64, int, error) {
	start := p.i

	var n int64

	for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
		if n = n*10 + int64(p.s[p.i]-'0'); n > deltatMaxTime {
			return 0, 0, errInvalidDuration
		}

		p.i++
	}

	if p.i == start {
		return 0, 0, errInvalidDuration
	}

	return n, p.i - start, nil
}

func (p *deltatParser) wsnum() (int64, error) {
	p.ws()

	neg := false
	if p.peek() == '-' {
		neg = true
		p.i++
	}

	n, _, err := p.digits()
	if err != nil {
		return 0, err
	}

	if neg {
		n = -n
	}

	return n, nil
}

func (p *deltatParser) short() (int64, error) {
	n, l, err := p.digits()
	if err != nil || l > 2 {
		return 0, errInvalidDuration
	}

	return n, nil
}

func (p *deltatParser) expect(c byte) error {
	if p.peek() != c {
		return errInvalidDuration
	}

	p.i++

	return nil
}

func (p *deltatParser) deltat() (int64, error) {
	n, err := p.wsnum()
	if err != nil {
		return 0, err
	}

	switch p.peek() {
	case 'd':
		p.i++

		rest, err := p.units("hms")
		if err != nil {
			return 0, err
		}

		return deltatSum(n, 0, 0, rest)
	case 'h', 'm', 's':
		return p.units("hms", n)
	case '-':
		p.i++

		var h, m, s int64

		if h, err = p.short(); err == nil {
			if err = p.expect(':'); err == nil {
				if m, err = p.short(); err == nil {
					if err = p.expect(':'); err == nil {
						s, err = p.short()
					}
				}
			}
		}

		if err != nil {
			return 0, err
		}

		return deltatSum(n, h, m, s)
	case ':':
		p.i++

		m, err := p.short()
		if err != nil {
			return 0, err
		}

		var s int64

		if p.peek() == ':' {
			p.i++

			if s, err = p.short(); err != nil {
				return 0, err
			}
		}

		return deltatSum(0, n, m, s)
	default:
		return deltatSum(0, 0, 0, n)
	}
}

func (p *deltatParser) units(allowed string, first ...int64) (int64, error) {
	var n int64

	if len(first) > 0 {
		n = first[0]
	} else {
		p.ws()

		if p.i == len(p.s) {
			return 0, nil
		}

		var err error
		if n, err = p.wsnum(); err != nil {
			return 0, err
		}
	}

	unit := p.peek()

	idx := -1

	for i := range len(allowed) {
		if allowed[i] == unit {
			idx = i
		}
	}

	if idx < 0 {
		return 0, errInvalidDuration
	}

	p.i++

	switch unit {
	case 'h':
		rest, err := p.units("ms")
		if err != nil {
			return 0, err
		}

		return deltatSum(0, n, 0, rest)
	case 'm':
		rest, err := p.units("s")
		if err != nil {
			return 0, err
		}

		return deltatSum(0, 0, n, rest)
	default:
		return deltatSum(0, 0, 0, n)
	}
}

func deltatSum(d, h, m, s int64) (int64, error) {
	if d > deltatMaxTime/deltatDay || d < deltatMinTime/deltatDay ||
		h > deltatMaxTime/deltatHour || h < deltatMinTime/deltatHour ||
		m > deltatMaxTime/60 || m < deltatMinTime/60 {
		return 0, errInvalidDuration
	}

	v := d*deltatDay + h*deltatHour + m*60 + s
	if v > deltatMaxTime || v < deltatMinTime {
		return 0, errInvalidDuration
	}

	return v, nil
}
