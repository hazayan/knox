package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type fido2HardwareOptions struct {
	Device  string
	PINFile string
	Origin  string
}

type fido2AssertionOptions struct {
	PublicKey struct {
		Challenge          string `json:"challenge"`
		RelyingPartyID     string `json:"rpId"`
		AllowedCredentials []struct {
			CredentialID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

type fido2RegistrationOptions struct {
	PublicKey struct {
		Challenge    string `json:"challenge"`
		RelyingParty struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		User struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
	} `json:"publicKey"`
}

func fido2HardwareLoginAssertion(options json.RawMessage, hw fido2HardwareOptions) ([]byte, error) {
	var parsed fido2AssertionOptions
	if err := json.Unmarshal(options, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse FIDO2 login options: %w", err)
	}
	if parsed.PublicKey.Challenge == "" {
		return nil, errors.New("FIDO2 login options missing challenge")
	}
	if len(parsed.PublicKey.AllowedCredentials) == 0 || parsed.PublicKey.AllowedCredentials[0].CredentialID == "" {
		return nil, errors.New("FIDO2 login options missing allowed credential")
	}
	credentialID, err := decodeBase64URL(parsed.PublicKey.AllowedCredentials[0].CredentialID, "credential id")
	if err != nil {
		return nil, err
	}
	rpID := strings.TrimSpace(parsed.PublicKey.RelyingPartyID)
	if rpID == "" {
		rpID = relyingPartyIDFromOrigin(hw.Origin)
	}
	clientData, err := fido2ClientData("webauthn.get", parsed.PublicKey.Challenge, hw.Origin)
	if err != nil {
		return nil, err
	}
	device, err := fido2DevicePath(hw.Device)
	if err != nil {
		return nil, err
	}
	pin, err := readFido2PIN(hw.PINFile)
	if err != nil {
		return nil, err
	}
	assertion, err := fido2GetAssertion(device, rpID, pin, credentialID, clientData)
	if err != nil {
		return nil, err
	}
	return fido2AssertionResponse(credentialID, clientData, assertion, nil)
}

func fido2HardwareRegistrationCredential(options json.RawMessage, hw fido2HardwareOptions) ([]byte, error) {
	var parsed fido2RegistrationOptions
	if err := json.Unmarshal(options, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse FIDO2 registration options: %w", err)
	}
	if parsed.PublicKey.Challenge == "" {
		return nil, errors.New("FIDO2 registration options missing challenge")
	}
	if parsed.PublicKey.RelyingParty.ID == "" {
		return nil, errors.New("FIDO2 registration options missing relying party id")
	}
	userID, err := decodeBase64URL(parsed.PublicKey.User.ID, "user id")
	if err != nil {
		return nil, err
	}
	clientData, err := fido2ClientData("webauthn.create", parsed.PublicKey.Challenge, hw.Origin)
	if err != nil {
		return nil, err
	}
	device, err := fido2DevicePath(hw.Device)
	if err != nil {
		return nil, err
	}
	pin, err := readFido2PIN(hw.PINFile)
	if err != nil {
		return nil, err
	}
	credential, err := fido2MakeCredential(
		device,
		parsed.PublicKey.RelyingParty.ID,
		parsed.PublicKey.RelyingParty.Name,
		pin,
		userID,
		parsed.PublicKey.User.Name,
		parsed.PublicKey.User.DisplayName,
		clientData,
	)
	if err != nil {
		return nil, err
	}
	attestationObject, err := fido2NoneAttestationObject(credential.AuthData)
	if err != nil {
		return nil, err
	}
	return fido2CredentialCreationResponse(credential.CredentialID, clientData, attestationObject)
}

func fido2ClientData(ceremony string, challenge string, origin string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"type":      ceremony,
		"challenge": challenge,
		"origin":    origin,
	})
}

func fido2DevicePath(device string) (string, error) {
	device = strings.TrimSpace(device)
	if device != "" && device != "auto" {
		return device, nil
	}
	return fido2FirstDevicePath()
}

func readFido2PIN(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read FIDO2 PIN file: %w", err)
	}
	pin := strings.TrimRight(string(data), "\r\n")
	if pin == "" {
		return "", errors.New("FIDO2 PIN file is empty")
	}
	return pin, nil
}

func fido2CredentialCreationResponse(credentialID, clientData, attestationObject []byte) ([]byte, error) {
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	return json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
		},
		"authenticatorAttachment": "cross-platform",
	})
}

func fido2AssertionResponse(credentialID, clientData []byte, assertion fido2HardwareAssertion, userHandle []byte) ([]byte, error) {
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	response := map[string]any{
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(assertion.AuthData),
		"signature":         base64.RawURLEncoding.EncodeToString(assertion.Signature),
	}
	if len(userHandle) != 0 {
		response["userHandle"] = base64.RawURLEncoding.EncodeToString(userHandle)
	}
	return json.Marshal(map[string]any{
		"id":                      id,
		"rawId":                   id,
		"type":                    "public-key",
		"response":                response,
		"authenticatorAttachment": "cross-platform",
	})
}
