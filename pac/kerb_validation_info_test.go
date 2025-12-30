package pac

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/go-krb5/x/rpc/mstypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-krb5/krb5/test/testdata"
)

func TestKerbValidationInfo_Unmarshal(t *testing.T) {
	t.Parallel()

	b, err := hex.DecodeString(testdata.MarshaledPAC_Kerb_Validation_Info_MS)
	require.NoError(t, err)

	var k KerbValidationInfo

	require.NoError(t, k.Unmarshal(b))

	assert.Equal(t, time.Date(2006, 4, 28, 1, 42, 50, 925640100, time.UTC), k.LogOnTime.Time())
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k.LogOffTime.Time())
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k.KickOffTime.Time())
	assert.Equal(t, time.Date(2006, 3, 18, 10, 44, 54, 837147900, time.UTC), k.PasswordLastSet.Time())
	assert.Equal(t, time.Date(2006, 3, 19, 10, 44, 54, 837147900, time.UTC), k.PasswordCanChange.Time())

	assert.Equal(t, "lzhu", k.EffectiveName.Value)
	assert.Equal(t, "Liqiang(Larry) Zhu", k.FullName.String())
	assert.Equal(t, "ntds2.bat", k.LogonScript.String())
	assert.Equal(t, "", k.ProfilePath.String())
	assert.Equal(t, "", k.HomeDirectory.String())
	assert.Equal(t, "", k.HomeDirectoryDrive.String())

	assert.Equal(t, uint16(4180), k.LogonCount)
	assert.Equal(t, uint16(0), k.BadPasswordCount)
	assert.Equal(t, uint32(2914711), k.UserID)
	assert.Equal(t, uint32(513), k.PrimaryGroupID)
	assert.Equal(t, uint32(26), k.GroupCount)

	gids := []mstypes.GroupMembership{
		{RelativeID: 3392609, Attributes: 7},
		{RelativeID: 2999049, Attributes: 7},
		{RelativeID: 3322974, Attributes: 7},
		{RelativeID: 513, Attributes: 7},
		{RelativeID: 2931095, Attributes: 7},
		{RelativeID: 3338539, Attributes: 7},
		{RelativeID: 3354830, Attributes: 7},
		{RelativeID: 3026599, Attributes: 7},
		{RelativeID: 3338538, Attributes: 7},
		{RelativeID: 2931096, Attributes: 7},
		{RelativeID: 3392610, Attributes: 7},
		{RelativeID: 3342740, Attributes: 7},
		{RelativeID: 3392630, Attributes: 7},
		{RelativeID: 3014318, Attributes: 7},
		{RelativeID: 2937394, Attributes: 7},
		{RelativeID: 3278870, Attributes: 7},
		{RelativeID: 3038018, Attributes: 7},
		{RelativeID: 3322975, Attributes: 7},
		{RelativeID: 3513546, Attributes: 7},
		{RelativeID: 2966661, Attributes: 7},
		{RelativeID: 3338434, Attributes: 7},
		{RelativeID: 3271401, Attributes: 7},
		{RelativeID: 3051245, Attributes: 7},
		{RelativeID: 3271606, Attributes: 7},
		{RelativeID: 3026603, Attributes: 7},
		{RelativeID: 3018354, Attributes: 7},
	}
	assert.Equal(t, gids, k.GroupIDs)

	assert.Equal(t, uint32(32), k.UserFlags)

	assert.Equal(t, mstypes.UserSessionKey{CypherBlock: [2]mstypes.CypherBlock{{Data: [8]byte{}}, {Data: [8]byte{}}}}, k.UserSessionKey)

	assert.Equal(t, "NTDEV-DC-05", k.LogonServer.Value)
	assert.Equal(t, "NTDEV", k.LogonDomainName.Value)

	assert.Equal(t, "S-1-5-21-397955417-626881126-188441444", k.LogonDomainID.String())

	assert.Equal(t, uint32(16), k.UserAccountControl)
	assert.Equal(t, uint32(0), k.SubAuthStatus)
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k.LastSuccessfulILogon.Time())
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k.LastFailedILogon.Time())
	assert.Equal(t, uint32(0), k.FailedILogonCount)

	assert.Equal(t, uint32(13), k.SIDCount)
	assert.Equal(t, int(k.SIDCount), len(k.ExtraSIDs))

	var es = []struct {
		sid  string
		attr uint32
	}{
		{"S-1-5-21-773533881-1816936887-355810188-513", uint32(7)},
		{"S-1-5-21-397955417-626881126-188441444-3101812", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3291368", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3291341", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3322973", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3479105", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3271400", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3283393", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3338537", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3038991", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3037999", uint32(536870919)},
		{"S-1-5-21-397955417-626881126-188441444-3248111", uint32(536870919)},
	}
	for i, s := range es {
		assert.Equal(t, s.sid, k.ExtraSIDs[i].SID.String())
		assert.Equal(t, s.attr, k.ExtraSIDs[i].Attributes)
	}

	assert.Equal(t, uint8(0), k.ResourceGroupDomainSID.SubAuthorityCount)
	assert.Equal(t, 0, len(k.ResourceGroupIDs))

	b, err = hex.DecodeString(testdata.MarshaledPAC_Kerb_Validation_Info)
	require.NoError(t, err)

	var k2 KerbValidationInfo

	require.NoError(t, k2.Unmarshal(b))

	assert.Equal(t, time.Date(2017, 5, 6, 15, 53, 11, 825766900, time.UTC), k2.LogOnTime.Time())
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k2.LogOffTime.Time())
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k2.KickOffTime.Time())
	assert.Equal(t, time.Date(2017, 5, 6, 7, 23, 8, 968750000, time.UTC), k2.PasswordLastSet.Time())
	assert.Equal(t, time.Date(2017, 5, 7, 7, 23, 8, 968750000, time.UTC), k2.PasswordCanChange.Time())

	assert.Equal(t, "testuser1", k2.EffectiveName.String())
	assert.Equal(t, "Test1 User1", k2.FullName.String())
	assert.Equal(t, "", k2.LogonScript.String())
	assert.Equal(t, "", k2.ProfilePath.String())
	assert.Equal(t, "", k2.HomeDirectory.String())
	assert.Equal(t, "", k2.HomeDirectoryDrive.String())

	assert.Equal(t, uint16(216), k2.LogonCount)
	assert.Equal(t, uint16(0), k2.BadPasswordCount)
	assert.Equal(t, uint32(1105), k2.UserID)
	assert.Equal(t, uint32(513), k2.PrimaryGroupID)
	assert.Equal(t, uint32(5), k2.GroupCount)

	gids = []mstypes.GroupMembership{
		{RelativeID: 513, Attributes: 7},
		{RelativeID: 1108, Attributes: 7},
		{RelativeID: 1109, Attributes: 7},
		{RelativeID: 1115, Attributes: 7},
		{RelativeID: 1116, Attributes: 7},
	}
	assert.Equal(t, gids, k2.GroupIDs)

	assert.Equal(t, uint32(32), k2.UserFlags)

	assert.Equal(t, mstypes.UserSessionKey{CypherBlock: [2]mstypes.CypherBlock{{Data: [8]byte{}}, {Data: [8]byte{}}}}, k2.UserSessionKey)

	assert.Equal(t, "ADDC", k2.LogonServer.Value)
	assert.Equal(t, "TEST", k2.LogonDomainName.Value)

	assert.Equal(t, "S-1-5-21-3167651404-3865080224-2280184895", k2.LogonDomainID.String())

	assert.Equal(t, uint32(528), k2.UserAccountControl)
	assert.Equal(t, uint32(0), k2.SubAuthStatus)
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k2.LastSuccessfulILogon.Time())
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k2.LastFailedILogon.Time())
	assert.Equal(t, uint32(0), k2.FailedILogonCount)

	assert.Equal(t, uint32(2), k2.SIDCount)
	assert.Equal(t, int(k2.SIDCount), len(k2.ExtraSIDs))

	var es2 = []struct {
		sid  string
		attr uint32
	}{
		{"S-1-5-21-3167651404-3865080224-2280184895-1114", uint32(536870919)},
		{"S-1-5-21-3167651404-3865080224-2280184895-1111", uint32(536870919)},
	}
	for i, s := range es2 {
		assert.Equal(t, s.sid, k2.ExtraSIDs[i].SID.String())
		assert.Equal(t, s.attr, k2.ExtraSIDs[i].Attributes)
	}

	assert.Equal(t, uint8(0), k2.ResourceGroupDomainSID.SubAuthorityCount)
	assert.Equal(t, 0, len(k2.ResourceGroupIDs))
}

func TestKerbValidationInfo_Unmarshal_DomainTrust(t *testing.T) {
	b, err := hex.DecodeString(testdata.MarshaledPAC_Kerb_Validation_Info_Trust)
	require.NoError(t, err)

	var k KerbValidationInfo

	require.NoError(t, k.Unmarshal(b))

	assert.Equal(t, time.Date(2017, 10, 14, 12, 03, 41, 52409900, time.UTC), k.LogOnTime.Time())
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k.LogOffTime.Time())
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551516, time.UTC), k.KickOffTime.Time())
	assert.Equal(t, time.Date(2017, 10, 10, 20, 42, 56, 220282300, time.UTC), k.PasswordLastSet.Time())
	assert.Equal(t, time.Date(2017, 10, 11, 20, 42, 56, 220282300, time.UTC), k.PasswordCanChange.Time())

	assert.Equal(t, "testuser1", k.EffectiveName.String())
	assert.Equal(t, "Test1 User1", k.FullName.String())
	assert.Equal(t, "", k.LogonScript.String())
	assert.Equal(t, "", k.ProfilePath.String())
	assert.Equal(t, "", k.HomeDirectory.String())
	assert.Equal(t, "", k.HomeDirectoryDrive.String())

	assert.Equal(t, uint16(46), k.LogonCount)
	assert.Equal(t, uint16(0), k.BadPasswordCount)
	assert.Equal(t, uint32(1106), k.UserID)
	assert.Equal(t, uint32(513), k.PrimaryGroupID)
	assert.Equal(t, uint32(3), k.GroupCount)

	gids := []mstypes.GroupMembership{
		{RelativeID: 1110, Attributes: 7},
		{RelativeID: 513, Attributes: 7},
		{RelativeID: 1109, Attributes: 7},
	}
	assert.Equal(t, gids, k.GroupIDs)

	assert.Equal(t, uint32(544), k.UserFlags)

	assert.Equal(t, mstypes.UserSessionKey{CypherBlock: [2]mstypes.CypherBlock{{Data: [8]byte{}}, {Data: [8]byte{}}}}, k.UserSessionKey)

	assert.Equal(t, "UDC", k.LogonServer.Value)
	assert.Equal(t, "USER", k.LogonDomainName.Value)

	assert.Equal(t, "S-1-5-21-2284869408-3503417140-1141177250", k.LogonDomainID.String())

	assert.Equal(t, uint32(528), k.UserAccountControl)
	assert.Equal(t, uint32(0), k.SubAuthStatus)
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k.LastSuccessfulILogon.Time())
	assert.Equal(t, time.Date(2185, 7, 21, 23, 34, 33, 709551616, time.UTC), k.LastFailedILogon.Time())
	assert.Equal(t, uint32(0), k.FailedILogonCount)

	assert.Equal(t, uint32(1), k.SIDCount)
	assert.Equal(t, int(k.SIDCount), len(k.ExtraSIDs))

	var es = []struct {
		sid  string
		attr uint32
	}{
		{"S-1-18-1", uint32(7)},
	}
	for i, s := range es {
		assert.Equal(t, s.sid, k.ExtraSIDs[i].SID.String())
		assert.Equal(t, s.attr, k.ExtraSIDs[i].Attributes)
	}

	assert.Equal(t, uint8(4), k.ResourceGroupDomainSID.SubAuthorityCount)
	assert.Equal(t, "S-1-5-21-3062750306-1230139592-1973306805", k.ResourceGroupDomainSID.String())
	assert.Equal(t, 2, len(k.ResourceGroupIDs))

	rgids := []mstypes.GroupMembership{
		{RelativeID: 1107, Attributes: 536870919},
		{RelativeID: 1108, Attributes: 536870919},
	}
	assert.Equal(t, rgids, k.ResourceGroupIDs)

	groupSids := []string{"S-1-5-21-2284869408-3503417140-1141177250-1110",
		"S-1-5-21-2284869408-3503417140-1141177250-513",
		"S-1-5-21-2284869408-3503417140-1141177250-1109",
		"S-1-18-1",
		"S-1-5-21-3062750306-1230139592-1973306805-1107",
		"S-1-5-21-3062750306-1230139592-1973306805-1108"}
	assert.Equal(t, groupSids, k.GetGroupMembershipSIDs())
}
