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
- Which encryption types the library will use is now decided by a configurable registry in the
  `github.com/go-krb5/krb5/crypto` package rather than being fixed at compile time, and the encryption types RFC 8429
  deprecates are no longer registered by default. `des3-cbc-sha1-kd` and `rc4-hmac` (with their `hmac-sha1-des3-kd` and
  `kerb-checksum-hmac-md5` checksum types) are still implemented but must be opted back in with
  `crypto.RegisterDeprecatedDes3CbcSha1Kd()` or `crypto.RegisterDeprecatedRC4HMAC()` during application start up. Until
  they are, `crypto.GetEType` and `crypto.GetChecksumEType` reject them, and `config.LibDefaults.DefaultTktEnctypeIDs`,
  `DefaultTGSEnctypeIDs` and `PermittedEnctypeIDs` exclude them so they are never advertised to a KDC. Active Directory
  deployments that have not been migrated off `rc4-hmac` will need the opt in.
- The encryption type lookup functions have been renamed so that `EType` is spelled consistently across the module, and
  the abbreviation `Chksum` is spelled out. Callers must be updated; there are no aliases under the old names:

  | Before                        | After                         |
  |:------------------------------|:------------------------------|
  | `crypto.GetEtype`             | `crypto.GetEType`             |
  | `crypto.GetChksumEtype`       | `crypto.GetChecksumEType`     |
  | `iana/etypeID.EtypeSupported` | `iana/etypeID.ETypeSupported` |

  The signatures are otherwise unchanged, except that `crypto.GetEType` and `crypto.GetChecksumEType` now return the
  single registered instance of an implementation rather than a fresh copy per call. The implementations this module
  provides are stateless empty structs so this is not observable for them, but an implementation registered by an
  application must be stateless and safe for concurrent use. Both functions also now return a pointer to the
  implementation, so a type assertion against the value type, such as `e.(crypto.Aes256CtsHmacSha96)`, must become
  `e.(*crypto.Aes256CtsHmacSha96)`.
- `iana/etypeID.ETypeSupported` is deprecated in addition to being renamed. It reports the fixed set of encryption types
  the module implements, which is no longer the same as the set it will use. Resolve the name with
  `etypeID.ETypesByName` and then check `crypto.GetEType` instead.
- The following functions are new in `github.com/go-krb5/krb5/crypto` and make up the registry. They are listed here
  only because they are the replacement for behaviour that used to be fixed at compile time; they break nothing on
  their own:

  | Function                                 | Purpose                                                     |
  |:-----------------------------------------|:------------------------------------------------------------|
  | `crypto.AddEType`                        | Register an encryption type implementation against an ID.   |
  | `crypto.DeleteEType`                     | Unregister an encryption type ID.                           |
  | `crypto.ETypeIDs`                        | List the registered encryption type IDs in ascending order. |
  | `crypto.AddChecksumEType`                | Register a checksum type implementation against an ID.      |
  | `crypto.DeleteChecksumEType`             | Unregister a checksum type ID.                              |
  | `crypto.ChecksumETypeIDs`                | List the registered checksum type IDs in ascending order.   |
  | `crypto.RegisterDeprecatedRC4HMAC`       | Opt back in to `rc4-hmac` and `kerb-checksum-hmac-md5`.     |
  | `crypto.RegisterDeprecatedDes3CbcSha1Kd` | Opt back in to `des3-cbc-sha1-kd` and `hmac-sha1-des3-kd`.  |
- `client.Client.ChangePasswd` and `kadmin.ChangePasswdMsg` now emit the original Kerberos change password protocol,
  protocol version `0x0001`, whose KRB_PRIV user data is the new password in the clear. They previously emitted the
  RFC 3244 set password protocol, protocol version `0xff80`, with the requestor's own principal name and realm in the
  `targname` and `targrealm` fields of the `ChangePasswdData`. Setting a password is an administrative operation, so on
  Active Directory the old message was rejected with `KRB5_KPASSWD_ACCESSDENIED` unless the requestor held the Reset
  Password extended right, which meant a principal could not change its own password. Their signatures are unchanged.
  This closes [jcmturner/gokrb5#387](https://github.com/jcmturner/gokrb5/issues/387) and
  [go-krb5/krb5#69](https://github.com/go-krb5/krb5/issues/69).
- Setting another principal's password is still available, now as an explicit operation rather than as the only thing
  `ChangePasswd` could do: `client.Client.SetPasswd` and `kadmin.SetPasswdMsg` send the RFC 3244 set password message
  naming a target principal. `kadmin.Request` has gained a `Version` field, set by `kadmin.ChangePasswdMsg` and
  `kadmin.SetPasswdMsg`, which selects which of the two protocols `kadmin.Request.Marshal` writes. A `kadmin.Request`
  constructed directly must set it to `kadmin.VersionChangePassword` or `kadmin.VersionSetPassword`; `Marshal` returns
  an error for any other value rather than writing a version number the KDC will reject.
- `spnego.NewKRB5TokenAPREQ` now returns an error, `spnego.ErrDelegationUnimplemented`, when `flagsGSSAPI` contains
  `gssapi.ContextFlagDeleg`, where previously it returned a token. RFC 4121 §4.1.1 requires an initiator that sets the
  delegation flag to populate the `DlgOpt`, `Dlgth` and `Deleg` fields that follow the context flags with the
  delegation option identifier and a `KRB_CRED`; this library emitted the flag with all three zeroed. MIT rejects that
  token with `GSS_S_FAILURE` once it reads `DlgOpt` as `0`, so no working deployment loses functionality — the change
  converts an opaque remote failure into a local one that names the cause. Credential delegation is not implemented;
  nothing in this library requests the flag, so only a caller passing `flagsGSSAPI` to `NewKRB5TokenAPREQ` directly is
  affected.
