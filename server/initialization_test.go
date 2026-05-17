package server

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hazayan/knox/pkg/types"
	"github.com/hazayan/knox/server/auth"
)

func TestInitializeStateCreatesFirstAdminAndRefusesSecondInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "init.json")

	state, err := InitializeState(path, InitializationOptions{
		AdminPrincipal: types.RawPrincipal{Type: "user", ID: "alice"},
		AdminGroups:    []string{"operators", "operators"},
		Time:           time.Unix(100, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("initialize state: %v", err)
	}
	if state.Version != InitializationStateVersion {
		t.Fatalf("unexpected version: %d", state.Version)
	}
	if len(state.AdminPrincipals) != 1 || state.AdminPrincipals[0].ID != "alice" {
		t.Fatalf("unexpected admin principals: %+v", state.AdminPrincipals)
	}
	if len(state.AdminGroups) != 1 || state.AdminGroups[0] != "operators" {
		t.Fatalf("unexpected admin groups: %+v", state.AdminGroups)
	}

	reloaded, err := LoadInitializationState(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if !reloaded.IsAdmin(auth.NewUser("alice", nil)) {
		t.Fatal("direct admin principal should be global admin")
	}
	if !reloaded.IsAdmin(auth.NewUser("bob", []string{"operators"})) {
		t.Fatal("admin group member should be global admin")
	}
	if reloaded.IsAdmin(auth.NewUser("mallory", nil)) {
		t.Fatal("unexpected admin access")
	}

	_, err = InitializeState(path, InitializationOptions{
		AdminPrincipal: types.RawPrincipal{Type: "user", ID: "alice"},
	})
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("expected already initialized error, got %v", err)
	}
}

func TestLoadInitializationStateMissingFile(t *testing.T) {
	_, err := LoadInitializationState(filepath.Join(t.TempDir(), "missing.json"))
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("expected not initialized error, got %v", err)
	}
}
