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
- `config.Load`, `config.NewFromString`, `config.NewFromReader` and `config.NewFromScanner` return an error when the
  scanner stops before the end of the input, where they previously returned the part of the configuration that had
  been read. `bufio.Scanner` halts at the first line longer than `bufio.MaxScanTokenSize`, 64 KiB, and at any read
  error, reporting either only through `Err()`, which was never called. A configuration whose tail was dropped came
  back indistinguishable from a complete one, so directives as consequential as `permitted_enctypes` could be
  missing with nothing to say so. A caller that was unknowingly relying on a truncated read now sees the error
  instead of the defaults.
- The `config` package now reads `krb5.conf` as MIT krb5's profile library does, from the MIT krb5 sources, and takes
  its defaults from those sources rather than from the documentation. A configuration that MIT krb5 accepts now
  loads with the same meaning, which changes how some configurations that were written for this library are read:

  - Only a line whose first non-blank character is `#` or `;` is a comment. A `#` or `;` later in a line is part of
    the value, as it is for MIT krb5, where `auth_to_local` rules commonly contain `;`. Configurations that relied on
    trailing comments must move them onto lines of their own.
  - Where a relation that takes a single value appears more than once, the first value is used, where previously the
    last one was. Sections and realms that appear more than once are merged rather than read as separate entries.
  - A `*` marks a section, subsection or relation final when it follows the section header, the tag or a closing
    brace, as `kdc* = host`. A `*` at the end of a value, as `kdc = host*`, was read as a final marker and is now part
    of the value.
  - Lines before the first section header are ignored, and so is everything up to the first line that begins with
    `[` in its first column. A closing brace closes one subsection whatever follows it on the line, a section header
    inside a subsection is an error, and `REALM = { kdc = host }` written on one line is a relation, not a realm.
  - `include` and `includedir` are now honoured where they were silently ignored, and a file or directory they name
    that does not exist is an error. A `module` directive is an error, since this library cannot load one.
  - The clock skew is read from `clockskew`, the name MIT krb5 uses, where the fork had renamed it to `clock_skew`,
    so a `clockskew` setting was silently ignored. `config.ConfigKeyClockSkew` changes accordingly.
  - `dns_lookup_kdc` defaults to `true` and `k5login_authoritative` to `true`, as they do in MIT krb5.
    `dns_lookup_kdc` and `dns_lookup_realm` fall back to `dns_fallback`. A realm without `kdc` entries is now
    located with DNS SRV records unless `dns_lookup_kdc = false` is set. `GetKpasswdServers` consults the
    configured `kpasswd_server` before DNS, and uses port 464 when it falls back to the admin servers found in DNS.
  - Booleans accept `y`, `yes`, `true`, `t`, `1` and `on`, and `n`, `no`, `false`, `nil`, `0` and `off`, in any
    case. `dns_canonicalize_hostname` also accepts `fallback`, which previously failed the whole load, and sets the
    new `LibDefaults.DNSCanonicalizeHostnameFallback`: the HTTP client then derives the service principal name from
    the hostname as given, and canonicalizes it with DNS only if the KDC reports the principal unknown.
  - Durations follow MIT krb5's `krb5_string_to_deltat` grammar. Go duration syntax that MIT krb5 does not accept,
    such as `1.5h` or `300ms`, is now an error.
  - Encryption type lists may be separated by commas, and accept `DEFAULT`, the families `aes`, `camellia`, `des3`
    and `rc4`, and a leading `+` or `-` to add or remove a type. `des3-cbc-sha1` names `des3-cbc-sha1-kd`, as it does
    for MIT krb5. `default_tkt_enctypes` and `default_tgs_enctypes` default to `permitted_enctypes`, and the default
    lists are MIT krb5's, which no longer name the single DES types.
  - `kdc_default_options` is read as a decimal number, or as hexadecimal with a `0x` prefix, where it was read as
    hexadecimal digits with or without the prefix. `udp_preference_limit` is capped at 32700 and a negative value
    means the default, where both were errors.
  - `kdc` and `kpasswd_server` entries are parsed as MIT krb5 parses them, so an IPv6 address in brackets is given
    the default port, and an entry with no host or an invalid port is an error.
  - `[domain_realm]` is matched as MIT krb5 matches it: an entry such as `example.com = REALM` maps the domain and
    every host below it, and a host given as an IP address is not mapped.
  - `default_ccache_name`, `default_keytab_name` and `default_client_keytab_name` have their `%{...}` parameters
    expanded, and an unknown parameter is an error.

  New in the package are `config.LoadDefault` and `config.LoadFiles`, which read `KRB5_CONFIG` or the platform's
  default files as MIT krb5 does, `config.DefaultPaths`, `config.ExpandPath`, `Config.LibDefaultsForRealm`, which
  applies a realm's subsection of `[libdefaults]` and is now used for the initial ticket request, and
  `Config.CCacheName`, `Config.KeytabName` and `Config.ClientKeytabName`, which give `KRB5CCNAME`, `KRB5_KTNAME` and
  `KRB5_CLIENT_KTNAME` precedence over the configuration as MIT krb5 does. `krberror.Krberror` now keeps the error it
  was created from, so `errors.As` reaches a `messages.KRBError` returned by the KDC.
