package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hazayan/knox/pkg/types"
)

var ErrPolicyNotFound = errors.New("policy not found")

type ACLPolicyStore struct {
	mu       sync.RWMutex
	path     string
	policies map[string]types.ACLPolicy
}

func NewACLPolicyStoreFromFile(path string) (*ACLPolicyStore, error) {
	store := &ACLPolicyStore{
		path:     path,
		policies: map[string]types.ACLPolicy{},
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
		return nil, fmt.Errorf("failed to read ACL policy file: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return store, nil
	}
	var policies []types.ACLPolicy
	if err := json.Unmarshal(data, &policies); err != nil {
		return nil, fmt.Errorf("failed to parse ACL policy file: %w", err)
	}
	for _, policy := range policies {
		if err := ValidateACLPolicy(policy); err != nil {
			return nil, err
		}
		store.policies[policy.Name] = normalizeACLPolicy(policy)
	}
	return store, nil
}

func (s *ACLPolicyStore) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.policies))
	for name := range s.policies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *ACLPolicyStore) Get(name string) (types.ACLPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	policy, ok := s.policies[name]
	if !ok {
		return types.ACLPolicy{}, ErrPolicyNotFound
	}
	return policy, nil
}

func (s *ACLPolicyStore) Put(policy types.ACLPolicy) error {
	if err := ValidateACLPolicy(policy); err != nil {
		return err
	}
	policy = normalizeACLPolicy(policy)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[policy.Name] = policy
	return s.writeLocked()
}

func (s *ACLPolicyStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[name]; !ok {
		return ErrPolicyNotFound
	}
	delete(s.policies, name)
	return s.writeLocked()
}

func (s *ACLPolicyStore) ACLForKey(keyID string) types.ACL {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var acl types.ACL
	for _, policy := range s.sortedPoliciesLocked() {
		for _, rule := range policy.Rules {
			if matchPolicyPattern(rule.Pattern, keyID) {
				for _, grant := range rule.Grants {
					acl = acl.Add(grant)
				}
			}
		}
	}
	return acl
}

func (s *ACLPolicyStore) writeLocked() error {
	if s.path == "" {
		return errors.New("ACL policy file is required")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("failed to create ACL policy directory: %w", err)
	}
	policies := s.sortedPoliciesLocked()
	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode ACL policies: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(s.path, data, 0o600)
}

func (s *ACLPolicyStore) sortedPoliciesLocked() []types.ACLPolicy {
	names := make([]string, 0, len(s.policies))
	for name := range s.policies {
		names = append(names, name)
	}
	sort.Strings(names)
	policies := make([]types.ACLPolicy, 0, len(names))
	for _, name := range names {
		policies = append(policies, s.policies[name])
	}
	return policies
}

func ValidateACLPolicy(policy types.ACLPolicy) error {
	if strings.TrimSpace(policy.Name) == "" {
		return errors.New("policy name must not be empty")
	}
	if len(policy.Rules) == 0 {
		return errors.New("policy must contain at least one rule")
	}
	for _, rule := range policy.Rules {
		if strings.TrimSpace(rule.Pattern) == "" {
			return errors.New("policy rule pattern must not be empty")
		}
		if len(rule.Grants) == 0 {
			return errors.New("policy rule grants must not be empty")
		}
		if err := types.ValidateACL(rule.Grants); err != nil {
			return fmt.Errorf("invalid policy grants: %w", err)
		}
	}
	return nil
}

func normalizeACLPolicy(policy types.ACLPolicy) types.ACLPolicy {
	policy.Name = strings.TrimSpace(policy.Name)
	for i := range policy.Rules {
		policy.Rules[i].Pattern = strings.TrimSpace(policy.Rules[i].Pattern)
	}
	return policy
}

func matchPolicyPattern(pattern, keyID string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(keyID, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == keyID
}

var aclPolicyResolver func(string) types.ACL

func SetACLPolicyResolver(resolver func(string) types.ACL) {
	aclPolicyResolver = resolver
}
