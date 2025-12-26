# krb5

[![GoDoc](https://godoc.org/github.com/go-krb5/krb5?status.svg)](https://godoc.org/github.com/go-krb5/krb5)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-krb5/krb5)](https://goreportcard.com/report/github.com/go-krb5/krb5)
[![Version](https://img.shields.io/github/release/go-krb5/krb5.svg)](https://github.com/go-krb5/krb5/releases)

Kerberos 5 implementation in pure go. 

## Thanks

This library literally could not exist without [Jonathan Turner](https://github.com/jcmturner). We are unaware of the circumstances but his
activity on GitHub seems to have ceased which is a significant loss for the community. Ultimately this is his org, and
we're just the current stewards.

* [Jonathan Turner](https://github.com/jcmturner) for the [Original and Related Repositories](https://github.com/jcmturner/gokrb5)
* Greg Hudson from the MIT Consortium for Kerberos and Internet Trust for providing useful advice.

## Features

* **Pure Go** - no dependency on external libraries 
* No platform specific code
* Server Side
  * HTTP handler wrapper implements SPNEGO Kerberos authentication
  * HTTP handler wrapper decodes Microsoft AD PAC authorization data
* Client Side
  * Client that can authenticate to an SPNEGO Kerberos authenticated web service
  * Ability to change client's password
* General
  * Kerberos libraries for custom integration
  * Parsing Keytab files
  * Parsing krb5.conf files
  * Parsing client credentials cache files such as `/tmp/krb5cc_$(id -u $(whoami))`

## Support

![Go version](https://img.shields.io/badge/Go-1.25-brightgreen.svg)

This library; unless otherwise explicitly expressed; will officially support versions of go which are currently
supported by the go maintainers (usually 3 minor versions) with a brief transition time (usually 1 patch release of go,
for example if go 1.21.0 is released, we will likely still support go 1.17 until go 1.21.1 is released). These specific
rules apply at the time of a published release.

This library in our opinion handles a critical element of security in a dependent project and we aim to avoid backwards
compatibility at the cost of security wherever possible. We also consider this especially important in a language like
go where their backwards compatibility when upgrading the compile tools is usually flawless.

Changes to the supported version of go in the positive direction (i.e. older versions deprecated and newer versions 
added) **_will never_** be considered a breaking change for this library.

This policy means that users who wish to build this with older versions of go may find there are features being used
which are not available in that version. The current intentionally supported versions of go are as follows:

- go 1.25
- ~~go 1.24~~ (not supported by `encoding/asn1` using `reflect.TypeAssert`)
- ~~go 1.23~~ (not supported by golang.org/x/crypto v0.42.0 and above)

## Additional Notes and Documentation

- [References](REFERENCE.md)
- [Breaking Changes](BREAKING.md)

## To Do

- [ ] Investigate mechanisms to have a encryption type registry to allow implementation of deprecated algorithms which
      are not enabled by default.
- CI Workflows:
  - [ ] Unit Tests
  - [ ] Integration Tests
  - [ ] Coverage
  - [ ] Renovate
- [ ] Document Breaking Changes
- [ ] Setup Governance
- [ ] Engage Community to assist in merging PR's and ensure they receive the adequate credit
- [ ] Overhaul go docs
- [ ] Error Cleanup and Overhaul

## Implementation

The following section contains some implementation specific information.

### Encryption & Checksum Types

|            Type            |        Implemented         | Encryption ID | Checksum ID |    Documentation     |
|:--------------------------:|:--------------------------:|:-------------:|:-----------:|:--------------------:|
|        des-cbc-crc         | No (deprecated, insecure)  |       1       |      x      | [RFC3961], [RFC6649] |
|        des-cbc-md4         | No (deprecated, insecure)  |       2       |      x      | [RFC3961], [RFC6649] |
|        des-cbc-md5         | No (deprecated, insecure)  |       3       |      x      | [RFC3961], [RFC6649] |
|        des3-cbc-md5        | No (deprecated, insecure)  |       5       |      x      | [RFC3961], [RFC8429] |
|       des3-cbc-sha1        | No (deprecated, insecure)  |       7       |     13      | [RFC3961], [RFC8429] |
|       des3-cbc-sha1        |             No             |       8       |     13      |      [RFC3961]       |
|      des3-cbc-sha1-kd      | Yes (deprecated, insecure) |      16       |     12      | [RFC3961], [RFC8429] |
|  aes128-cts-hmac-sha1-96   |            Yes             |      17       |     15      |      [RFC3962]       |
|  aes256-cts-hmac-sha1-96   |            Yes             |      18       |     16      |      [RFC3962]       |
| aes128-cts-hmac-sha256-128 |            Yes             |      19       |     19      |      [RFC8009]       |
| aes256-cts-hmac-sha384-192 |            Yes             |      20       |     20      |      [RFC8009]       |
|          rc4-hmac          |            Yes             |      23       |    -138     |      [RFC4757]       |

[RFC3961]: https://datatracker.ietf.org/doc/html/rfc3961
[RFC3962]: https://datatracker.ietf.org/doc/html/rfc3962
[RFC8009]: https://datatracker.ietf.org/doc/html/rfc8009
[RFC4757]: https://datatracker.ietf.org/doc/html/rfc4757
[RFC6649]: https://datatracker.ietf.org/doc/html/rfc6649
[RFC8429]: https://datatracker.ietf.org/doc/html/rfc8429

### Tested Scenarios

The following is working/tested:

* Tested against MIT KDC (1.6.3 is the oldest version tested against) and Microsoft Active Directory (Windows 2008 R2)
* Tested against a KDC that supports PA-FX-FAST.
* Tested against users that have pre-authentication required using PA-ENC-TIMESTAMP.
* Microsoft PAC Authorization Data is processed and exposed in the HTTP request context. Available if Microsoft Active Directory is used as the KDC.

## Known Issues

| Issue                                                                                                                                                                                                                         | Worked around?                                                    | References                                          |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|-----------------------------------------------------|
| The Go standard library's encoding/asn1 package cannot unmarshal into slice of asn1.RawValue                                                                                                                                  | Yes                                                               | https://github.com/golang/go/issues/17321           |
| The Go standard library's encoding/asn1 package cannot marshal into a GeneralString                                                                                                                                           | Yes - using https://github.com/go-krb/x/tree/master/encoding/asn1 | https://github.com/golang/go/issues/18832           |
| The Go standard library's encoding/asn1 package cannot marshal into slice of strings and pass stringtype parameter tags to members                                                                                            | Yes - using https://github.com/go-krb/x/tree/master/encoding/asn1 | https://github.com/golang/go/issues/18834           |
| The Go standard library's encoding/asn1 package cannot marshal with application tags                                                                                                                                          | Yes                                                               |                                                     |
| The Go standard library's x/crypto/pbkdf2.Key function uses the int type for iteraction count limiting meaning the 4294967296 count specified in https://tools.ietf.org/html/rfc3962 section 4 cannot be met on 32bit systems | Yes - using https://github.com/go-crypt/x/tree/master/pbkdf2      | https://go-review.googlesource.com/c/crypto/+/85535 |
