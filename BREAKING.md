# Breaking Changes

## Fork

The following breaking changes exist between `github.com/jcmturner/gokrb5/v8` and `github.com/go-krb5/krb5` v0 (each
change will be elaborated on in time):

- Package `github.com/go-krb5/krb5/iana/asnAppTag` renamed to `github.com/go-krb5/krb5/iana/asn1apptag` (being evaluated
  to be moved to `encoding/asn1`).
- Removal of v7 package and v8 package is now v0.
- Context Value Key for `github.com/go-krb5/krb5/spnego` has changed to const `CTXKey` with an explicit type.
- The struct tag `generalstring` in the `github.com/go-krb5/x/encoding/asn1` package is now `general`. It's unlikely
  anyone was using this however instances of `generalstring` (case-sensitive) in struct asn1 tags should be evaluated
  manually and changed appropriately.
- `messages.APReq.Verify` now compares the client realm in the authenticator against the client realm in the ticket's
  encrypted part, as required by RFC 4120 §3.2.3, and rejects a mismatch with `KRB_AP_ERR_BADMATCH`. Correspondingly the
  `*credentials.Credentials` returned by `service.VerifyAPREQ` now carries the client name and realm from the
  KDC-sealed encrypted part of the ticket rather than from the client-supplied authenticator. This closes
  [jcmturner/gokrb5#577](https://github.com/jcmturner/gokrb5/issues/577), where a client could authenticate with a
  ticket for its own principal while presenting an arbitrary realm as its identity.
