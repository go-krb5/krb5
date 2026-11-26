package credentials

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/types"
)

func TestResolveCCache(t *testing.T) {
	const realm = "TEST.GOKRB5"
	var (
		now    = time.Unix(1700000000, 0)
		dir    = t.TempDir()
		file   = filepath.Join(dir, "krb5cc")
		socket = filepath.Join(dir, "kcm.sock")
		c      = NewV4CCache()
		user   = types.PrincipalName{
			NameType:   1,
			NameString: []string{"testuser"},
		}
	)
	c.SetDefaultPrincipal(NewPrincipal(user, realm))
	for _, s := range [][]string{{"krbtgt", realm}, {"MSSQLSvc", "sql:1433"}} {
		server := types.PrincipalName{
			NameType:   2,
			NameString: s,
		}
		c.AddCredential(&Credential{
			Client: NewPrincipal(user, realm),
			Server: NewPrincipal(server, realm),
			Key: types.EncryptionKey{
				KeyType:  18,
				KeyValue: make([]byte, 32),
			},
			AuthTime:    now,
			StartTime:   now,
			EndTime:     now.Add(time.Hour),
			RenewTill:   now.Add(time.Hour),
			TicketFlags: types.NewKrbFlags(),
			Ticket:      []byte(s[0]),
		})
	}
	want, err := c.Marshal()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(file, want, 0o600))

	// A KCM daemon serving c as the default cache, 1000.
	endian := c.getEndian()
	princ, err := c.writePrincipal(c.DefaultPrincipal, endian)
	require.NoError(t, err)
	creds := make([][]byte, len(c.Credentials))
	for i, cred := range c.Credentials {
		creds[i], err = c.writeCredential(cred, endian)
		require.NoError(t, err)
	}
	l, err := net.Listen("unix", socket)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			for {
				var n [4]byte
				if _, err := io.ReadFull(conn, n[:]); err != nil {
					break
				}
				req := make([]byte, binary.BigEndian.Uint32(n[:]))
				if _, err := io.ReadFull(conn, req); err != nil {
					break
				}
				var (
					op     = binary.BigEndian.Uint16(req[2:4])
					args   = req[4:]
					status uint32
					reply  []byte
				)
				switch {
				case op == kcmOpGetDefaultCache:
					reply = []byte("1000\x00")
				case !bytes.HasPrefix(args, []byte("1000\x00")):
					status = kcmErrNoCache
				case op == kcmOpGetPrincipal:
					reply = princ
				case op == kcmOpGetCredUUIDList:
					reply = make([]byte, kcmUUIDLen*len(creds))
					for i := range creds {
						reply[i*kcmUUIDLen] = byte(i)
					}
				case op == kcmOpGetCredByUUID:
					reply = creds[args[5]]
				}
				size := 4 + len(reply)
				if size > kcmMaxReply {
					break
				}
				resp := binary.BigEndian.AppendUint32(nil, uint32(size))
				resp = binary.BigEndian.AppendUint32(resp, 0)
				resp = binary.BigEndian.AppendUint32(resp, status)
				if _, err := conn.Write(append(resp, reply...)); err != nil {
					break
				}
			}
			conn.Close()
		}
	}()

	cfg, err := config.NewFromString("[libdefaults]\nkcm_socket = " + socket)
	require.NoError(t, err)
	for _, name := range []string{"FILE:" + file, file, "KCM:", "KCM:1000"} {
		got, err := ResolveCCache(name, cfg)
		require.NoError(t, err, name)
		b, err := got.Marshal()
		require.NoError(t, err, name)
		require.Equal(t, want, b, name)
	}
	_, err = ResolveCCache("KCM:1001", cfg)
	require.EqualError(
		t, err,
		"credential cache KCM:1001: no credentials cache found",
	)
	_, err = ResolveCCache("KEYRING:persistent:1000", cfg)
	require.EqualError(
		t, err,
		"credential cache type KEYRING is not supported",
	)
	cfg, err = config.NewFromString("[libdefaults]\nkcm_socket = -")
	require.NoError(t, err)
	_, err = ResolveCCache("KCM:", cfg)
	require.EqualError(t, err, "kcm is disabled by kcm_socket")
}
