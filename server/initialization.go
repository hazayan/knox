package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hazayan/knox/pkg/types"
)

const InitializationStateVersion = 1

var ErrAlreadyInitialized = errors.New("knox is already initialized")
var ErrNotInitialized = errors.New("knox is not initialized")

type InitializationState struct {
	Version         int                  `json:"version"`
	InitializedAt   time.Time            `json:"initialized_at"`
	AdminPrincipals []types.RawPrincipal `json:"admin_principals"`
	AdminGroups     []string             `json:"admin_groups,omitempty"`
}

type InitializationOptions struct {
	AdminPrincipal types.RawPrincipal
	AdminGroups    []string
	Time           time.Time
}

func LoadInitializationState(path string) (*InitializationState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotInitialized
		}
		return nil, fmt.Errorf("failed to read initialization state: %w", err)
	}
	var state InitializationState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse initialization state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	return &state, nil
}

func InitializeState(path string, opts InitializationOptions) (*InitializationState, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("initialization state file is required")
	}
	if _, err := os.Stat(path); err == nil {
		return nil, ErrAlreadyInitialized
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to stat initialization state: %w", err)
	}
	if opts.Time.IsZero() {
		opts.Time = time.Now().UTC()
	}
	state := InitializationState{
		Version:         InitializationStateVersion,
		InitializedAt:   opts.Time.UTC(),
		AdminPrincipals: []types.RawPrincipal{opts.AdminPrincipal},
		AdminGroups:     compactUnique(opts.AdminGroups),
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode initialization state: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create initialization state directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrAlreadyInitialized
		}
		return nil, fmt.Errorf("failed to create initialization state: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write initialization state: %w", err)
	}
	return &state, nil
}

func (s InitializationState) Validate() error {
	if s.Version != InitializationStateVersion {
		return fmt.Errorf("unsupported initialization state version: %d", s.Version)
	}
	if s.InitializedAt.IsZero() {
		return errors.New("initialization state is missing initialized_at")
	}
	if len(s.AdminPrincipals) == 0 && len(s.AdminGroups) == 0 {
		return errors.New("initialization state must contain at least one admin principal or group")
	}
	for _, principal := range s.AdminPrincipals {
		if err := validateRawPrincipal(principal); err != nil {
			return err
		}
	}
	for _, group := range s.AdminGroups {
		if strings.TrimSpace(group) == "" {
			return errors.New("initialization admin group must not be empty")
		}
	}
	return nil
}

func (s InitializationState) IsAdmin(principal types.Principal) bool {
	if principal == nil {
		return false
	}
	for _, raw := range principal.Raw() {
		for _, admin := range s.AdminPrincipals {
			if raw.Type == admin.Type && raw.ID == admin.ID {
				return true
			}
		}
	}
	for _, group := range s.AdminGroups {
		if principal.CanAccess(types.ACL{{Type: types.UserGroup, ID: group, AccessType: types.Admin}}, types.Admin) {
			return true
		}
	}
	return false
}

func validateRawPrincipal(principal types.RawPrincipal) error {
	id := strings.TrimSpace(principal.ID)
	if id == "" {
		return errors.New("initialization admin principal id must not be empty")
	}
	switch principal.Type {
	case "user", "machine", "service":
		return nil
	default:
		return fmt.Errorf("unsupported initialization admin principal type: %s", principal.Type)
	}
}

func compactUnique(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
