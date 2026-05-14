package main

import (
	"fmt"
	"os"

	"github.com/hazayan/knox/pkg/crypto"
	"github.com/spf13/cobra"
)

type keyCommandOptions struct {
	backend            string
	encryptedKeyFile   string
	metadataFile       string
	backupMetadataFile string
	device             string
	pinFile            string
	rpID               string
	rpName             string
	deriveInfo         string
	masterKeyFile      string
	input              string
	output             string
}

func newKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage Knox server master-key storage",
	}
	cmd.AddCommand(newKeyFido2EnrollCommand())
	cmd.AddCommand(newKeyInitCommand())
	cmd.AddCommand(newKeyMigrateCommand())
	cmd.AddCommand(newKeyUnlockTestCommand())
	cmd.AddCommand(newKeyBackupCommand())
	cmd.AddCommand(newKeyRestoreCommand())
	return cmd
}

func newKeyFido2EnrollCommand() *cobra.Command {
	var opts keyCommandOptions
	cmd := &cobra.Command{
		Use:   "fido2-enroll",
		Short: "Create Knox FIDO2 credential metadata",
		RunE: func(_ *cobra.Command, _ []string) error {
			metadata, err := crypto.EnrollFido2Metadata(opts.rpID, opts.rpName, opts.deriveInfo, fido2DeviceOptions(opts))
			if err != nil {
				return err
			}
			if err := crypto.SaveFido2Metadata(opts.metadataFile, metadata); err != nil {
				return err
			}
			fmt.Printf("wrote fido2 metadata to %s\n", opts.metadataFile)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.metadataFile, "metadata-file", "/usr/local/etc/knox/fido2-credential.json", "FIDO2 credential metadata file")
	cmd.Flags().StringVar(&opts.rpID, "rp-id", "", "FIDO2 relying party ID")
	cmd.Flags().StringVar(&opts.rpName, "rp-name", "", "FIDO2 relying party display name")
	cmd.Flags().StringVar(&opts.deriveInfo, "derive-info", crypto.DefaultFido2DeriveInfo, "HKDF info label")
	addFido2DeviceFlags(cmd, &opts)
	mustMarkRequired(cmd, "rp-id")
	return cmd
}

func newKeyInitCommand() *cobra.Command {
	var opts keyCommandOptions
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize encrypted Knox master-key storage",
		RunE: func(_ *cobra.Command, _ []string) error {
			wrapping, err := wrappingProvider(opts)
			if err != nil {
				return err
			}
			masterKey, err := crypto.GenerateMasterKey()
			if err != nil {
				return err
			}
			defer clearLocalBytes(masterKey)
			bundle, err := crypto.EncryptMasterKeyBundle(masterKey, wrapping, crypto.MasterKeyBundleKind)
			if err != nil {
				return err
			}
			if err := crypto.WriteMasterKeyBundleFile(opts.encryptedKeyFile, bundle); err != nil {
				return err
			}
			fmt.Printf("initialized encrypted master key at %s\n", opts.encryptedKeyFile)
			return nil
		},
	}
	addMasterKeyBundleFlags(cmd, &opts)
	return cmd
}

func newKeyMigrateCommand() *cobra.Command {
	var opts keyCommandOptions
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate plaintext file master key to encrypted storage",
		RunE: func(_ *cobra.Command, _ []string) error {
			wrapping, err := wrappingProvider(opts)
			if err != nil {
				return err
			}
			masterKey, err := loadPlainMasterKeyFile(opts.masterKeyFile)
			if err != nil {
				return err
			}
			defer clearLocalBytes(masterKey)
			bundle, err := crypto.EncryptMasterKeyBundle(masterKey, wrapping, crypto.MasterKeyBundleKind)
			if err != nil {
				return err
			}
			if err := crypto.WriteMasterKeyBundleFile(opts.encryptedKeyFile, bundle); err != nil {
				return err
			}
			fmt.Printf("migrated master key into %s\n", opts.encryptedKeyFile)
			return nil
		},
	}
	addMasterKeyBundleFlags(cmd, &opts)
	cmd.Flags().StringVar(&opts.masterKeyFile, "master-key-file", "/etc/knox/master.key", "Plaintext master key file to migrate")
	return cmd
}

func newKeyUnlockTestCommand() *cobra.Command {
	var opts keyCommandOptions
	cmd := &cobra.Command{
		Use:   "unlock-test",
		Short: "Verify encrypted Knox master-key storage can be unlocked",
		RunE: func(_ *cobra.Command, _ []string) error {
			wrapping, err := wrappingProvider(opts)
			if err != nil {
				return err
			}
			masterKey, err := crypto.DecryptMasterKeyBundleFile(opts.encryptedKeyFile, wrapping)
			if err != nil {
				return err
			}
			defer clearLocalBytes(masterKey)
			fmt.Printf("unlock test succeeded for %s\n", opts.encryptedKeyFile)
			return nil
		},
	}
	addMasterKeyBundleFlags(cmd, &opts)
	return cmd
}

func newKeyBackupCommand() *cobra.Command {
	var opts keyCommandOptions
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Export an encrypted Knox master-key backup artifact",
		RunE: func(_ *cobra.Command, _ []string) error {
			inputWrapping, err := wrappingProvider(opts)
			if err != nil {
				return err
			}
			backupMetadataFile := opts.backupMetadataFile
			if backupMetadataFile == "" {
				backupMetadataFile = opts.metadataFile
			}
			outputWrapping, err := wrappingProvider(keyCommandOptions{
				backend:      opts.backend,
				metadataFile: backupMetadataFile,
				device:       opts.device,
				pinFile:      opts.pinFile,
			})
			if err != nil {
				return err
			}
			backup, err := crypto.BackupMasterKeyBundle(opts.encryptedKeyFile, inputWrapping, outputWrapping)
			if err != nil {
				return err
			}
			if err := crypto.WriteMasterKeyBundleFile(opts.output, backup); err != nil {
				return err
			}
			fmt.Printf("wrote encrypted master-key backup to %s\n", opts.output)
			return nil
		},
	}
	addMasterKeyBundleFlags(cmd, &opts)
	cmd.Flags().StringVar(&opts.backupMetadataFile, "backup-fido2-metadata-file", "", "FIDO2 metadata file used to encrypt the backup artifact")
	cmd.Flags().StringVar(&opts.output, "output", "", "Backup artifact output path")
	mustMarkRequired(cmd, "output")
	return cmd
}

func newKeyRestoreCommand() *cobra.Command {
	var opts keyCommandOptions
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore an encrypted Knox master-key backup artifact",
		RunE: func(_ *cobra.Command, _ []string) error {
			outputWrapping, err := wrappingProvider(opts)
			if err != nil {
				return err
			}
			backupMetadataFile := opts.backupMetadataFile
			if backupMetadataFile == "" {
				backupMetadataFile = opts.metadataFile
			}
			backupWrapping, err := wrappingProvider(keyCommandOptions{
				backend:      opts.backend,
				metadataFile: backupMetadataFile,
				device:       opts.device,
				pinFile:      opts.pinFile,
			})
			if err != nil {
				return err
			}
			backup, err := os.ReadFile(opts.input)
			if err != nil {
				return fmt.Errorf("failed to read backup artifact: %w", err)
			}
			bundle, err := crypto.RestoreMasterKeyBundle(backup, backupWrapping, outputWrapping)
			if err != nil {
				return err
			}
			if err := crypto.WriteMasterKeyBundleFile(opts.encryptedKeyFile, bundle); err != nil {
				return err
			}
			fmt.Printf("restored encrypted master key to %s\n", opts.encryptedKeyFile)
			return nil
		},
	}
	addMasterKeyBundleFlags(cmd, &opts)
	cmd.Flags().StringVar(&opts.backupMetadataFile, "backup-fido2-metadata-file", "", "FIDO2 metadata file used to decrypt the backup artifact")
	cmd.Flags().StringVar(&opts.input, "input", "", "Backup artifact input path")
	mustMarkRequired(cmd, "input")
	return cmd
}

func addMasterKeyBundleFlags(cmd *cobra.Command, opts *keyCommandOptions) {
	cmd.Flags().StringVar(&opts.backend, "backend", "fido2", "Master key wrapping backend")
	cmd.Flags().StringVar(&opts.encryptedKeyFile, "encrypted-key-file", "/var/db/knox/master.key.fido2", "Encrypted Knox master-key bundle path")
	cmd.Flags().StringVar(&opts.metadataFile, "fido2-metadata-file", "/usr/local/etc/knox/fido2-credential.json", "FIDO2 credential metadata file")
	addFido2DeviceFlags(cmd, opts)
}

func wrappingProvider(opts keyCommandOptions) (crypto.WrappingKeyProvider, error) {
	switch opts.backend {
	case "fido2":
		return crypto.NewFido2WrappingKeyProviderFromMetadataFileWithOptions(opts.metadataFile, fido2DeviceOptions(opts))
	default:
		return nil, fmt.Errorf("unsupported wrapping backend: %s", opts.backend)
	}
}

func addFido2DeviceFlags(cmd *cobra.Command, opts *keyCommandOptions) {
	cmd.Flags().StringVar(&opts.device, "fido2-device", "auto", "FIDO2 device path or auto")
	cmd.Flags().StringVar(&opts.pinFile, "fido2-pin-file", "", "File containing the FIDO2 PIN")
}

func fido2DeviceOptions(opts keyCommandOptions) crypto.Fido2DeviceOptions {
	return crypto.Fido2DeviceOptions{
		Device:  opts.device,
		PinFile: opts.pinFile,
	}
}

func loadPlainMasterKeyFile(path string) ([]byte, error) {
	previousEnv := os.Getenv("KNOX_MASTER_KEY")
	previous := os.Getenv("KNOX_MASTER_KEY_FILE")
	if err := os.Unsetenv("KNOX_MASTER_KEY"); err != nil {
		return nil, err
	}
	if err := os.Setenv("KNOX_MASTER_KEY_FILE", path); err != nil {
		return nil, err
	}
	defer func() {
		if previousEnv != "" {
			_ = os.Setenv("KNOX_MASTER_KEY", previousEnv)
		}
		if previous == "" {
			_ = os.Unsetenv("KNOX_MASTER_KEY_FILE")
		} else {
			_ = os.Setenv("KNOX_MASTER_KEY_FILE", previous)
		}
	}()
	return crypto.LoadMasterKeyWithConfig(crypto.MasterKeyConfig{Backend: "file"})
}

func clearLocalBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func mustMarkRequired(cmd *cobra.Command, name string) {
	if err := cmd.MarkFlagRequired(name); err != nil {
		panic(err)
	}
}
