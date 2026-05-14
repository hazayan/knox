//go:build !libfido2

package crypto

import "errors"

func fido2EnrollCredential(_ string, _ string, _ Fido2DeviceOptions) ([]byte, error) {
	return nil, errors.New("knox was built without libfido2 support; rebuild with -tags libfido2")
}

func fido2HMACSecret(_ Fido2CredentialMetadata, _ Fido2DeviceOptions) ([]byte, error) {
	return nil, errors.New("knox was built without libfido2 support; rebuild with -tags libfido2")
}
