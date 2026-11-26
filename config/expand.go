package config

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
)

var errUnresolvableToken = errors.New("the token names an MIT krb5 installation directory")

// ExpandPath expands the parameters MIT krb5 expands in the relations of krb5.conf that name files, such as
// default_ccache_name and default_keytab_name: %{TEMP}, %{uid}, %{euid}, %{USERID}, %{null} and %{username}. An
// unknown parameter or one missing its closing brace is an error, as it is for MIT krb5. %{LIBDIR}, %{BINDIR} and
// %{SBINDIR} name directories of an MIT krb5 installation and are reported as an error too.
func ExpandPath(path string) (string, error) {
	var b strings.Builder

	for {
		start := strings.Index(path, "%{")
		if start < 0 {
			b.WriteString(path)

			return b.String(), nil
		}

		b.WriteString(path[:start])

		end := strings.IndexByte(path[start:], '}')
		if end < 0 {
			return "", fmt.Errorf("parameter in %q is missing its closing brace", path)
		}

		v, err := expandToken(path[start+2 : start+end])
		if err != nil {
			return "", fmt.Errorf("parameter %q: %w", path[start:start+end+1], err)
		}

		b.WriteString(v)

		path = path[start+end+1:]
	}
}

func expandToken(token string) (string, error) {
	switch token {
	case "TEMP":
		if d := os.Getenv("TMPDIR"); d != "" {
			return d, nil
		}

		return "/tmp", nil
	case "uid", "USERID":
		return userID(os.Getuid())
	case "euid":
		return userID(os.Geteuid())
	case "null":
		return "", nil
	case "username":
		u, err := user.LookupId(strconv.Itoa(os.Geteuid()))
		if err != nil {
			return "", err
		}

		return u.Username, nil
	case "LIBDIR", "BINDIR", "SBINDIR":
		return "", errUnresolvableToken
	default:
		return "", errors.New("unknown parameter")
	}
}

func userID(id int) (string, error) {
	if runtime.GOOS == "windows" {
		u, err := user.Current()
		if err != nil {
			return "", err
		}

		return u.Uid, nil
	}

	return strconv.Itoa(id), nil
}
