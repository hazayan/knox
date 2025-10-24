package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/hazayan/knox/pkg/config"
	"github.com/hazayan/knox/pkg/observability/logging"
)

func TestConfigCommands(t *testing.T) {
	var originalCfgFile string
	t.Run("ConfigInitCommand", func(t *testing.T) {
		t.Run("Init_Success", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()
			// Remove the config file that was created by NewTestConfig
			os.Remove(tc.ConfigFile)

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigInitCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"--server", "knox.example.com:9000"})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Expected no error, got: %v. Error output: %s", err, buf.String())
			}

			// Verify config file was created
			if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
				t.Fatal("Config file was not created")
			}

			// Load and verify config
			loadedCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			if loadedCfg.CurrentProfile != "default" {
				t.Errorf("Expected current profile 'default', got '%s'", loadedCfg.CurrentProfile)
			}

			profile, exists := loadedCfg.Profiles["default"]
			if !exists {
				t.Fatal("Default profile not found")
			}

			if profile.Server != "knox.example.com:9000" {
				t.Errorf("Expected server 'knox.example.com:9000', got '%s'", profile.Server)
			}

			if !profile.Cache.Enabled {
				t.Error("Expected cache to be enabled")
			}

			output := buf.String()
			if !strings.Contains(output, "Configuration initialized") {
				t.Errorf("Expected success message, got: %s", output)
			}
		})

		t.Run("Init_ForceOverwrite", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile
			originalCfgFile := cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			// Create initial config
			initialCfg := &config.ClientConfig{
				CurrentProfile: "old",
				Profiles: map[string]config.ClientProfile{
					"old": {
						Server: "old.example.com:9000",
					},
				},
			}
			if err := config.SaveClientConfig(cfgFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigInitCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"--server", "new.example.com:9000", "--force"})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			// Verify config was overwritten
			loadedCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			profile := loadedCfg.Profiles["default"]
			if profile.Server != "new.example.com:9000" {
				t.Errorf("Expected server 'new.example.com:9000', got '%s'", profile.Server)
			}
		})

		t.Run("Init_ConfigExistsNoForce", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile
			originalCfgFile := cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			// Create initial config
			initialCfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "existing.example.com:9000",
					},
				},
			}
			if err := config.SaveClientConfig(cfgFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigInitCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			output := buf.String()
			if !strings.Contains(output, "Config file already exists") {
				t.Errorf("Expected 'already exists' message, got: %s", output)
			}
			if !strings.Contains(output, "Use --force to overwrite") {
				t.Errorf("Expected '--force' suggestion, got: %s", output)
			}

			// Verify config was not overwritten
			loadedCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			profile := loadedCfg.Profiles["default"]
			if profile.Server != "existing.example.com:9000" {
				t.Errorf("Expected server 'existing.example.com:9000', got '%s'", profile.Server)
			}
		})
	})

	t.Run("ConfigShowCommand", func(t *testing.T) {
		t.Run("Show_Success", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile before creating test config
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			// Create test config
			testCfg := &config.ClientConfig{
				CurrentProfile: "production",
				Profiles: map[string]config.ClientProfile{
					"production": {
						Server: "prod.example.com:9000",
						Cache: config.CacheConfig{
							Enabled: true,
						},
					},
					"staging": {
						Server: "staging.example.com:9000",
						Cache: config.CacheConfig{
							Enabled: false,
						},
					},
				},
			}
			if err := config.SaveClientConfig(cfgFile, testCfg); err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigShowCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{})

			// Global cfgFile already set above

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			output := buf.String()
			if !strings.Contains(output, "Configuration file:") {
				t.Errorf("Expected config file header, got: %s", output)
			}
			if !strings.Contains(output, "Current profile: production") {
				t.Errorf("Expected current profile 'production', got: %s", output)
			}
			if !strings.Contains(output, "prod.example.com:9000") {
				t.Errorf("Expected production server 'prod.example.com:9000', got: %s", output)
			}
			if !strings.Contains(output, "staging.example.com:9000") {
				t.Errorf("Expected staging server 'staging.example.com:9000', got: %s", output)
			}
		})

		t.Run("Show_JSONOutput", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile
			originalCfgFile := cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			// Create test config
			testCfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "localhost:9000",
					},
				},
			}
			if err := config.SaveClientConfig(cfgFile, testCfg); err != nil {
				t.Fatalf("Failed to create test config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigShowCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"--json"})

			jsonOutput = true
			defer func() { jsonOutput = false }()

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			var result config.ClientConfig
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal JSON output: %v", err)
			}

			if result.CurrentProfile != "default" {
				t.Errorf("Expected current profile 'default', got '%s'", result.CurrentProfile)
			}
			if _, exists := result.Profiles["default"]; !exists {
				t.Error("Default profile not found in JSON output")
			}
		})

		t.Run("Show_ConfigNotFound", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()
			cfgFile := tc.ConfigFile

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigShowCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Expected error for missing config, got none")
			}
			if !strings.Contains(err.Error(), "failed to load config") {
				t.Errorf("Expected 'failed to load config' error, got: %v", err)
			}
		})
	})

	t.Run("ConfigProfileCommands", func(t *testing.T) {
		t.Run("ProfileAdd_Success", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()
			// Create initial config
			initialCfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "localhost:9000",
					},
				},
			}
			if err := config.SaveClientConfig(tc.ConfigFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileAddCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"production", "--server", "prod.example.com:9000"})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			// Verify profile was added
			loadedCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			profile, exists := loadedCfg.Profiles["production"]
			if !exists {
				t.Fatal("Production profile not found")
			}

			if profile.Server != "prod.example.com:9000" {
				t.Errorf("Expected server 'prod.example.com:9000', got '%s'", profile.Server)
			}

			output := buf.String()
			if !strings.Contains(output, "Profile added: production") {
				t.Errorf("Expected success message, got: %s", output)
			}
		})

		t.Run("ProfileAdd_AlreadyExists", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile before creating initial config
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			// Create initial config with existing profile
			initialCfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "localhost:9000",
					},
				},
			}
			if err := config.SaveClientConfig(cfgFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileAddCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"default", "--server", "new.example.com:9000"})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Expected error for existing profile, got none")
			}

			if !strings.Contains(err.Error(), "already exists") {
				t.Errorf("Expected 'already exists' error, got: %v", err)
			}
		})

		t.Run("ProfileAdd_AlreadyExists", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile
			originalCfgFile := cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			// Create initial config with existing profile
			initialCfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "localhost:9000",
					},
					"staging": {
						Server: "staging.example.com:9000",
					},
				},
			}
			if err := config.SaveClientConfig(cfgFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileRemoveCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"staging"})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			// Verify profile was removed
			loadedCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			if _, exists := loadedCfg.Profiles["staging"]; exists {
				t.Error("Staging profile should have been removed")
			}

			output := buf.String()
			if !strings.Contains(output, "Profile removed: staging") {
				t.Errorf("Expected success message, got: %s", output)
			}
		})

		t.Run("ProfileRemove_Success", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile
			originalCfgFile := cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			// Create initial config with multiple profiles
			initialCfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "localhost:9000",
					},
					"staging": {
						Server: "staging.example.com:9000",
					},
				},
			}
			if err := config.SaveClientConfig(cfgFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileRemoveCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"nonexistent"})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Expected error for nonexistent profile, got none")
			}
			if !strings.Contains(err.Error(), "not found") {
				t.Errorf("Expected 'not found' error, got: %v", err)
			}
		})

		t.Run("ProfileRemove_CurrentProfile", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()
			// Create initial config
			initialCfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "localhost:9000",
					},
				},
			}
			if err := config.SaveClientConfig(tc.ConfigFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileRemoveCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"default"})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Expected error for current profile removal, got none")
			}
			if !strings.Contains(err.Error(), "cannot remove current profile") {
				t.Errorf("Expected 'cannot remove current profile' error, got: %v", err)
			}
		})

		t.Run("ProfileUse_Success", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()
			// Create initial config
			initialCfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "localhost:9000",
					},
					"production": {
						Server: "production.example.com:9000",
					},
				},
			}
			if err := config.SaveClientConfig(tc.ConfigFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileUseCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"production"})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Expected no error, got: %v. Output: %s", err, buf.String())
			}

			// Verify current profile was updated
			loadedCfg, err := config.LoadClientConfig(cfgFile)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			if loadedCfg.CurrentProfile != "production" {
				t.Errorf("Expected current profile 'production', got '%s'", loadedCfg.CurrentProfile)
			}

			output := buf.String()
			if !strings.Contains(output, "Switched to profile: production") {
				t.Errorf("Expected success message, got: %s", output)
			}
		})

		t.Run("ProfileRemove_NotFound", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()
			// Create initial config
			initialCfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "localhost:9000",
					},
				},
			}
			if err := config.SaveClientConfig(tc.ConfigFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileUseCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"nonexistent"})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Expected error for nonexistent profile, got none")
			}
			if !strings.Contains(err.Error(), "not found") {
				t.Errorf("Expected 'not found' error, got: %v", err)
			}
		})

		t.Run("ProfileList_Success", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()
			// Set global cfgFile before creating initial config
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			// Create initial config
			initialCfg := &config.ClientConfig{
				CurrentProfile: "production",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "localhost:9000",
						Cache: config.CacheConfig{
							Enabled: true,
						},
					},
					"production": {
						Server: "prod.example.com:9000",
						Cache: config.CacheConfig{
							Enabled: false,
						},
					},
				},
			}
			if err := config.SaveClientConfig(cfgFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileListCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{})

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			output := buf.String()
			if !strings.Contains(output, "Available profiles:") {
				t.Errorf("Expected profiles header, got: %s", output)
			}
			if !strings.Contains(output, "* production") {
				t.Errorf("Expected current profile marker, got: %s", output)
			}
			if !strings.Contains(output, "default") {
				t.Errorf("Expected default profile, got: %s", output)
			}
		})

		t.Run("ProfileList_JSONOutput", func(t *testing.T) {
			tc := NewTestConfig(t)
			defer tc.Cleanup()

			// Set global cfgFile before creating initial config
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			// Create initial config
			initialCfg := &config.ClientConfig{
				CurrentProfile: "default",
				Profiles: map[string]config.ClientProfile{
					"default": {
						Server: "localhost:9000",
					},
				},
			}
			if err := config.SaveClientConfig(cfgFile, initialCfg); err != nil {
				t.Fatalf("Failed to create initial config: %v", err)
			}

			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileListCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"--json"})

			// Override global cfgFile for this test
			originalCfgFile = cfgFile
			cfgFile = tc.ConfigFile
			defer func() { cfgFile = originalCfgFile }()

			err := cmd.Execute()
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			var result map[string]config.ClientProfile
			if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
				t.Fatalf("Failed to unmarshal JSON output: %v", err)
			}

			if _, exists := result["default"]; !exists {
				t.Error("Default profile not found in JSON output")
			}
		})
	})

	t.Run("ConfigCommandValidation", func(t *testing.T) {
		t.Run("ProfileAdd_MissingServer", func(t *testing.T) {
			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileAddCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"test"}) // Missing --server flag

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Expected error for missing server, got none")
			}
		})

		t.Run("ProfileAdd_MissingName", func(t *testing.T) {
			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileAddCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{}) // Missing profile name

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Expected error for missing profile name, got none")
			}
		})

		t.Run("ProfileRemove_MissingName", func(t *testing.T) {
			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileRemoveCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{}) // Missing profile name

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Expected error for missing profile name, got none")
			}
		})

		t.Run("ProfileUse_MissingName", func(t *testing.T) {
			var buf bytes.Buffer
			logger = logging.NewCLILogger(false, &buf)

			cmd := newConfigProfileUseCmd()
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{}) // Missing profile name

			err := cmd.Execute()
			if err == nil {
				t.Fatal("Expected error for missing profile name, got none")
			}
		})
	})
}
