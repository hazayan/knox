package server

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/auth"
)

func TestACLPolicyStorePersistsAndMatchesPrefixPolicies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policies.json")
	store, err := NewACLPolicyStoreFromFile(path)
	if err != nil {
		t.Fatalf("new policy store: %v", err)
	}

	policy := types.ACLPolicy{
		Name: "trust-services",
		Rules: []types.ACLPolicyRule{
			{
				Pattern: "service:kanidm:*",
				Grants: types.ACL{
					{Type: types.UserGroup, ID: "knox-admins", AccessType: types.Admin},
					{Type: types.Machine, ID: "machine-a", AccessType: types.Read},
				},
			},
		},
	}
	if err := store.Put(policy); err != nil {
		t.Fatalf("put policy: %v", err)
	}

	reloaded, err := NewACLPolicyStoreFromFile(path)
	if err != nil {
		t.Fatalf("reload policy store: %v", err)
	}
	matching := reloaded.ACLForKey("service:kanidm:prod:tls")
	if len(matching) != 2 {
		t.Fatalf("expected two matching grants, got %+v", matching)
	}
	if reloaded.ACLForKey("service:kunci:prod:pin") != nil {
		t.Fatal("unexpected grants for non-matching key")
	}
}

func TestACLPolicyStoreDeleteMissingPolicy(t *testing.T) {
	store, err := NewACLPolicyStoreFromFile(filepath.Join(t.TempDir(), "policies.json"))
	if err != nil {
		t.Fatalf("new policy store: %v", err)
	}
	if err := store.Delete("missing"); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("expected policy-not-found, got %v", err)
	}
}

func TestNewKeyAppliesMatchingACLPolicyGrants(t *testing.T) {
	SetACLPolicyResolver(func(keyID string) types.ACL {
		if keyID != "service:kanidm:prod:tls" {
			return nil
		}
		return types.ACL{
			{Type: types.UserGroup, ID: "knox-admins", AccessType: types.Admin},
		}
	})
	defer SetACLPolicyResolver(nil)

	key := newKey("service:kanidm:prod:tls", nil, []byte("secret"), auth.NewUser("alice", nil))
	if !auth.NewUser("bob", []string{"knox-admins"}).CanAccess(key.ACL, types.Admin) {
		t.Fatalf("expected policy grant in key ACL: %+v", key.ACL)
	}
	if !auth.NewUser("alice", nil).CanAccess(key.ACL, types.Admin) {
		t.Fatalf("creator should retain admin access: %+v", key.ACL)
	}
}
