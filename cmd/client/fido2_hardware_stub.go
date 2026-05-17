//go:build !libfido2 || !cgo

package main

import "errors"

type fido2HardwareCredential struct {
	CredentialID []byte
	AuthData     []byte
}

type fido2HardwareAssertion struct {
	AuthData  []byte
	Signature []byte
}

func fido2FirstDevicePath() (string, error) {
	return "", errors.New("knox was built without libfido2 support; rebuild with -tags libfido2")
}

func fido2MakeCredential(_ string, _ string, _ string, _ string, _ []byte, _ string, _ string, _ []byte) (fido2HardwareCredential, error) {
	return fido2HardwareCredential{}, errors.New("knox was built without libfido2 support; rebuild with -tags libfido2")
}

func fido2GetAssertion(_ string, _ string, _ string, _ []byte, _ []byte) (fido2HardwareAssertion, error) {
	return fido2HardwareAssertion{}, errors.New("knox was built without libfido2 support; rebuild with -tags libfido2")
}

func fido2NoneAttestationObject(_ []byte) ([]byte, error) {
	return nil, errors.New("knox was built without libfido2 support; rebuild with -tags libfido2")
}
