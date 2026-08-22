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
  token with `GSS_S_FAILURE` once it reads `DlgOpt` as `0`, so no working deployment loses functionality ; the change
  converts an opaque remote failure into a local one that names the cause. Credential delegation is not implemented;
  nothing in this library requests the flag, so only a caller passing `flagsGSSAPI` to `NewKRB5TokenAPREQ` directly is
  affected. **This entry has been superseded by the one below**: credential delegation is now implemented, and
  `spnego.ErrDelegationUnimplemented` no longer exists.
- `spnego.ErrDelegationUnimplemented` has been removed. Credential delegation is now implemented, so nothing can
  return it; code matching on it will no longer compile. Requesting `gssapi.ContextFlagDeleg`, or passing the new
  `spnego.Delegation()` option, now obtains a forwarded ticket-granting ticket and carries it in the AP-REQ as
  RFC 4121 Section 4.1.1 requires. Note that this adds a TGS exchange with the KDC during context establishment,
  and that it requires `forwardable = true` in the `libdefaults` section of `krb5.conf`: the KDC will not forward a
  ticket it did not mark forwardable, and this library defaults the setting to `false`.
- Acceptors now read the delegation fields of the AP-REQ authenticator checksum, and reject an AP-REQ that claims a
  delegation they cannot fully process with `KRB_AP_ERR_INAPP_CKSUM`, where they previously authenticated it and
  silently ignored the delegation. `service.VerifyAPREQ` extracts unconditionally ; there is no `Settings` opt in ;
  and every defect past the `GSS_C_DELEG_FLAG` bit is fatal: a 28 octet checksum with `DlgOpt` zeroed, which is
  precisely what this library itself emitted before the entry above, a `Dlgth` running past the end of the checksum,
  a `KRB_CRED` that will not unmarshal, and a `KRB_CRED` encrypted with an encryption type this library does not
  have registered. Nothing runs unless the peer set the delegation flag, so a client that does not request
  delegation is unaffected. This is deliberate: an acceptor has no `ret_flags` channel on which to tell an initiator
  that its forwarded ticket was discarded, so accepting the request while dropping the credential would leave the
  initiator believing a delegation happened that did not. Services that must keep authenticating such clients need
  those clients fixed or the encryption type registered with `crypto.AddEType`.
- `service.Cache.IsReplay` and `service.Cache.AddEntry` take the service principal's realm as a new second argument,
  `IsReplay(sname types.PrincipalName, srealm string, a types.Authenticator)`, and the replay cache is now keyed on
  the whole tuple RFC 4120 §3.2.3 describes: the client name and realm, the service name and realm, and the
  authenticator's `ctime` and `cusec`. Previously an entry was keyed on the client and the time alone, with the
  service name held as its value and compared on lookup, so a presentation under a second service name both failed
  to match the stored entry and *replaced* it; which §3.2.3 forbids: "If a server loses track of authenticators
  presented within the allowable clock skew, it MUST reject all requests until the clock skew interval has passed."
  Callers of these two methods must add the argument; there is no compatibility shim, because silently keying on an
  empty realm would reintroduce the collision between a service principal registered in more than one realm.

  `service.VerifyAPREQ` additionally now records a presentation against the service principal whose key **decrypted**
  the ticket rather than against the `SName` the ticket carries in its unencrypted portion. Where
  `service.KeytabPrincipal` overrides the keytab lookup those differ, and the ticket's copy is covered by no
  checksum, so a captured AP-REQ could be replayed indefinitely by rewriting it: each rewrite missed the entry that
  should have caught it and displaced that entry for the next attempt. Deployments using `KeytabPrincipal` had no
  working replay protection at all. No configuration change is needed to pick the fix up, and without the override
  the two values are identical, so nothing changes for acceptors that do not set it.
- `spnego.Client.Do` stops with an error at a redirect that leaves the host the configured service principal name
  belongs to, where it previously followed the redirect and negotiated against the new host. The header carrying the
  old ticket was already deleted before a redirect was followed, but the negotiation that started again at the target
  used the configured name verbatim, so the client minted a fresh service ticket for the host the caller named and
  sent it to whichever host the redirect pointed at. That AP-REQ has never been seen by the real service, so its
  replay cache does not hold it, and nothing binds it to the connection it arrived on unless channel bindings are
  configured: the redirect target can relay it and authenticate as the user. The comparison is on the host alone,
  since the derived name carries no port, so a redirect to another port on the same host is still followed. Clients
  constructed with an empty SPN are unaffected, the name being derived per request from the host actually addressed.
  A deployment that relies on a redirect to another hostname must construct the client with an empty SPN and let it
  derive the name, or handle the redirect itself and call `Do` again for the new host.
- The AP-REQ authenticator key usage is decided by where the AP_REQ sits rather than by what its ticket names.
  RFC 4120 Section 7.5.1 assigns usage 7 to the "TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator" and usage 11 to an
  AP-REQ authenticator, and the library previously chose between them by testing whether the ticket's first name
  component was `krbtgt`. Renewing a service ticket sends that ticket as the credential in the TGS-REQ, so its
  authenticator was encrypted with 11 where every KDC derives with 7: renewal failed with
  `KRB_AP_ERR_BAD_INTEGRITY`, and `client.Client.GetCachedTicket` renews whenever a cached ticket is past its end
  time but inside `renew_till`. Renewal now works, and no configuration change is needed to pick it up. The
  converse case changes on the wire: an AP-REQ presenting a TGT, which is the user-to-user exchange of RFC 4120
  Section 3.7, is now built and verified with usage 11 where it previously used 7 in both directions. That agrees
  with MIT and with the specification, but a peer running an older version of this library on the other side of a
  user-to-user exchange will not interoperate with it.
