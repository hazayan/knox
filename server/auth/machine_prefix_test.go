package auth

import (
	"testing"

	"github.com/hazayan/knox/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestMachinePrefixSecurity tests security constraints for machine prefix matching.
func TestMachinePrefixSecurity(t *testing.T) {
	tests := []struct {
		name           string
		machineID      string
		aclEntry       types.Access
		expectedAccess bool
	}{
		{
			name:      "ValidPrefixMatch",
			machineID: "web-server-01",
			aclEntry: types.Access{
				Type:       types.MachinePrefix,
				ID:         "web-server",
				AccessType: types.Read,
			},
			expectedAccess: true,
		},
		{
			name:      "PrefixTooShort",
			machineID: "web-server-01",
			aclEntry: types.Access{
				Type:       types.MachinePrefix,
				ID:         "we", // Only 2 characters
				AccessType: types.Read,
			},
			expectedAccess: false,
		},
		{
			name:      "EmptyPrefix",
			machineID: "web-server-01",
			aclEntry: types.Access{
				Type:       types.MachinePrefix,
				ID:         "", // Empty prefix
				AccessType: types.Read,
			},
			expectedAccess: false,
		},
		{
			name:      "NoPrefixMatch",
			machineID: "web-server-01",
			aclEntry: types.Access{
				Type:       types.MachinePrefix,
				ID:         "db-server", // Different prefix
				AccessType: types.Read,
			},
			expectedAccess: false,
		},
		{
			name:      "ExactMachineMatch",
			machineID: "web-server-01",
			aclEntry: types.Access{
				Type:       types.Machine,
				ID:         "web-server-01", // Exact match, not prefix
				AccessType: types.Read,
			},
			expectedAccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine := NewMachine(tt.machineID)
			acl := types.ACL{tt.aclEntry}

			hasAccess := machine.CanAccess(acl, types.Read)
			assert.Equal(t, tt.expectedAccess, hasAccess,
				"Machine %s with ACL %s should have access=%v",
				tt.machineID, tt.aclEntry.ID, tt.expectedAccess)
		})
	}
}
