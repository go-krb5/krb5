// Package nametype provides Kerberos 5 principal name type numbers.
package nametype

// Kerberos name type IDs.
const (
	// Name type not known.
	KRB_NT_UNKNOWN int32 = 0

	// Just the name of the principal as in DCE,  or for users.
	KRB_NT_PRINCIPAL int32 = 1

	// Service and other unique instance (krbtgt).
	KRB_NT_SRV_INST int32 = 2

	// Service with host name as instance (telnet, rcommands).
	KRB_NT_SRV_HST int32 = 3

	// Service with host as remaining components.
	KRB_NT_SRV_XHST int32 = 4

	// Unique ID.
	KRB_NT_UID int32 = 5

	// Encoded X.509 Distinguished name [RFC2253].
	KRB_NT_X500_PRINCIPAL int32 = 6

	// Name in form of SMTP email name (e.g., user@example.com).
	KRB_NT_SMTP_NAME int32 = 7

	// Enterprise name; may be mapped to principal name.
	KRB_NT_ENTERPRISE int32 = 10
)
