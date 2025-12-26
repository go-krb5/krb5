package pac

import (
	"bytes"
	"fmt"

	"github.com/go-krb5/x/rpc/mstypes"
	"github.com/go-krb5/x/rpc/ndr"
)

// DeviceInfo implements https://msdn.microsoft.com/en-us/library/hh536402.aspx
type DeviceInfo struct {
	// A 32-bit unsigned integer that contains the RID of the account. If the UserId member equals 0x00000000, the first group SID in this member is the SID for this account.
	UserID uint32

	// A 32-bit unsigned integer that contains the RID for the primary group to which this account belongs.
	PrimaryGroupID uint32

	// A SID structure that contains the SID for the domain of the account.This member is used in conjunction with the UserId, and GroupIds members to create the user and group SIDs for the client.
	AccountDomainID mstypes.RPCSID `ndr:"pointer"`

	// A 32-bit unsigned integer that contains the number of groups within the account domain to which the account belongs.
	AccountGroupCount uint32

	// A pointer to a list of GROUP_MEMBERSHIP (section 2.2.2) structures that contains the groups to which the account belongs in the account domain. The number of groups in this list MUST be equal to GroupCount.
	AccountGroupIDs []mstypes.GroupMembership `ndr:"pointer,conformant"`

	// A 32-bit unsigned integer that contains the total number of SIDs present in the ExtraSids member.
	SIDCount uint32

	// A pointer to a list of KERB_SID_AND_ATTRIBUTES structures that contain a list of SIDs corresponding to groups not in domains. If the UserId member equals 0x00000000, the first group SID in this member is the SID for this account.
	ExtraSIDs []mstypes.KerbSidAndAttributes `ndr:"pointer,conformant"`

	// A 32-bit unsigned integer that contains the number of domains with groups to which the account belongs.
	DomainGroupCount uint32

	// A pointer to a list of DOMAIN_GROUP_MEMBERSHIP structures (section 2.2.3) that contains the domains to which the account belongs to a group. The number of sets in this list MUST be equal to DomainCount.
	DomainGroup []mstypes.DomainGroupMembership `ndr:"pointer,conformant"`
}

// Unmarshal bytes into the DeviceInfo struct.
func (k *DeviceInfo) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b))

	err = dec.Decode(k)
	if err != nil {
		err = fmt.Errorf("error unmarshaling DeviceInfo: %v", err)
	}

	return
}
