//go:build libfido2 && cgo

package crypto

/*
#cgo pkg-config: libfido2
#include <stdlib.h>
#include <string.h>
#include <fido.h>

enum {
	KNOX_FIDO2_ERR_ALLOC = -1,
	KNOX_FIDO2_ERR_DEVICE = -2,
	KNOX_FIDO2_ERR_CREDENTIAL = -3,
	KNOX_FIDO2_ERR_ASSERTION = -4,
	KNOX_FIDO2_ERR_RESULT = -5,
};

static int knox_fido2_first_device_path(char **out) {
	const size_t max_devices = 64;
	fido_dev_info_t *devlist = NULL;
	const fido_dev_info_t *di = NULL;
	size_t found = 0;
	const char *path = NULL;

	*out = NULL;
	devlist = fido_dev_info_new(max_devices);
	if (devlist == NULL) {
		return KNOX_FIDO2_ERR_ALLOC;
	}
	if (fido_dev_info_manifest(devlist, max_devices, &found) != FIDO_OK || found == 0) {
		fido_dev_info_free(&devlist, max_devices);
		return KNOX_FIDO2_ERR_DEVICE;
	}
	di = fido_dev_info_ptr(devlist, 0);
	path = fido_dev_info_path(di);
	if (path == NULL || path[0] == '\0') {
		fido_dev_info_free(&devlist, max_devices);
		return KNOX_FIDO2_ERR_DEVICE;
	}
	*out = strdup(path);
	fido_dev_info_free(&devlist, max_devices);
	if (*out == NULL) {
		return KNOX_FIDO2_ERR_ALLOC;
	}
	return FIDO_OK;
}

static int knox_fido2_enroll(
	const char *device_path,
	const char *rp_id,
	const char *rp_name,
	const char *pin,
	const unsigned char *client_data,
	size_t client_data_len,
	const unsigned char *user_id,
	size_t user_id_len,
	unsigned char **credential_id,
	size_t *credential_id_len
) {
	fido_dev_t *dev = NULL;
	fido_cred_t *cred = NULL;
	int rc = FIDO_OK;
	const unsigned char *id = NULL;
	size_t id_len = 0;

	*credential_id = NULL;
	*credential_id_len = 0;

	dev = fido_dev_new();
	cred = fido_cred_new();
	if (dev == NULL || cred == NULL) {
		rc = KNOX_FIDO2_ERR_ALLOC;
		goto out;
	}
	if ((rc = fido_dev_open(dev, device_path)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_cred_set_clientdata(cred, client_data, client_data_len)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_cred_set_rp(cred, rp_id, rp_name)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_cred_set_user(cred, user_id, user_id_len, "knox", "Knox", NULL)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_cred_set_extensions(cred, FIDO_EXT_HMAC_SECRET)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_cred_set_rk(cred, FIDO_OPT_FALSE)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_cred_set_uv(cred, FIDO_OPT_FALSE)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_dev_make_cred(dev, cred, pin)) != FIDO_OK) {
		goto out;
	}
	id = fido_cred_id_ptr(cred);
	id_len = fido_cred_id_len(cred);
	if (id == NULL || id_len == 0) {
		rc = KNOX_FIDO2_ERR_RESULT;
		goto out;
	}
	*credential_id = malloc(id_len);
	if (*credential_id == NULL) {
		rc = KNOX_FIDO2_ERR_ALLOC;
		goto out;
	}
	memcpy(*credential_id, id, id_len);
	*credential_id_len = id_len;

out:
	if (dev != NULL) {
		(void)fido_dev_close(dev);
		fido_dev_free(&dev);
	}
	if (cred != NULL) {
		fido_cred_free(&cred);
	}
	return rc;
}

static int knox_fido2_hmac_secret(
	const char *device_path,
	const char *rp_id,
	const char *pin,
	const unsigned char *client_data,
	size_t client_data_len,
	const unsigned char *credential_id,
	size_t credential_id_len,
	const unsigned char *salt,
	size_t salt_len,
	unsigned char **secret,
	size_t *secret_len
) {
	fido_dev_t *dev = NULL;
	fido_assert_t *assert = NULL;
	int rc = FIDO_OK;
	const unsigned char *ptr = NULL;
	size_t len = 0;

	*secret = NULL;
	*secret_len = 0;

	dev = fido_dev_new();
	assert = fido_assert_new();
	if (dev == NULL || assert == NULL) {
		rc = KNOX_FIDO2_ERR_ALLOC;
		goto out;
	}
	if ((rc = fido_dev_open(dev, device_path)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_assert_set_clientdata(assert, client_data, client_data_len)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_assert_set_rp(assert, rp_id)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_assert_set_extensions(assert, FIDO_EXT_HMAC_SECRET)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_assert_allow_cred(assert, credential_id, credential_id_len)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_assert_set_hmac_salt(assert, salt, salt_len)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_assert_set_up(assert, FIDO_OPT_TRUE)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_assert_set_uv(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_dev_get_assert(dev, assert, pin)) != FIDO_OK) {
		goto out;
	}
	ptr = fido_assert_hmac_secret_ptr(assert, 0);
	len = fido_assert_hmac_secret_len(assert, 0);
	if (ptr == NULL || len == 0) {
		rc = KNOX_FIDO2_ERR_RESULT;
		goto out;
	}
	*secret = malloc(len);
	if (*secret == NULL) {
		rc = KNOX_FIDO2_ERR_ALLOC;
		goto out;
	}
	memcpy(*secret, ptr, len);
	*secret_len = len;

out:
	if (dev != NULL) {
		(void)fido_dev_close(dev);
		fido_dev_free(&dev);
	}
	if (assert != NULL) {
		fido_assert_free(&assert);
	}
	return rc;
}

static const char *knox_fido2_strerr(int rc) {
	switch (rc) {
	case KNOX_FIDO2_ERR_ALLOC:
		return "allocation failed";
	case KNOX_FIDO2_ERR_DEVICE:
		return "no FIDO2 device found";
	case KNOX_FIDO2_ERR_CREDENTIAL:
		return "credential operation failed";
	case KNOX_FIDO2_ERR_ASSERTION:
		return "assertion operation failed";
	case KNOX_FIDO2_ERR_RESULT:
		return "FIDO2 device returned no usable result";
	default:
		return fido_strerr(rc);
	}
}
*/
import "C"

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"
)

var fido2InitOnce sync.Once

var (
	fido2ClientData = []byte("knox-fido2-master-key-wrapping")
	fido2UserID     = []byte("knox-server")
)

func fido2EnrollCredential(rpID, rpName string, options Fido2DeviceOptions) ([]byte, error) {
	devicePath, err := resolveFido2Device(options.Device)
	if err != nil {
		return nil, err
	}
	pin, err := loadFido2PIN(options.PinFile)
	if err != nil {
		return nil, err
	}
	cDevicePath := C.CString(devicePath)
	cRPID := C.CString(rpID)
	cRPName := C.CString(rpName)
	var cPIN *C.char
	if pin != "" {
		cPIN = C.CString(pin)
	}
	defer C.free(unsafe.Pointer(cDevicePath))
	defer C.free(unsafe.Pointer(cRPID))
	defer C.free(unsafe.Pointer(cRPName))
	if cPIN != nil {
		defer C.free(unsafe.Pointer(cPIN))
	}

	var credentialID *C.uchar
	var credentialIDLen C.size_t
	rc := C.knox_fido2_enroll(
		cDevicePath,
		cRPID,
		cRPName,
		cPIN,
		(*C.uchar)(unsafe.Pointer(&fido2ClientData[0])),
		C.size_t(len(fido2ClientData)),
		(*C.uchar)(unsafe.Pointer(&fido2UserID[0])),
		C.size_t(len(fido2UserID)),
		&credentialID,
		&credentialIDLen,
	)
	if rc != C.FIDO_OK {
		return nil, fido2Error("enroll fido2 credential", int(rc))
	}
	defer C.free(unsafe.Pointer(credentialID))
	return C.GoBytes(unsafe.Pointer(credentialID), C.int(credentialIDLen)), nil
}

func fido2HMACSecret(metadata Fido2CredentialMetadata, options Fido2DeviceOptions) ([]byte, error) {
	if err := metadata.Validate(); err != nil {
		return nil, err
	}
	devicePath, err := resolveFido2Device(options.Device)
	if err != nil {
		return nil, err
	}
	pin, err := loadFido2PIN(options.PinFile)
	if err != nil {
		return nil, err
	}
	credentialID, err := base64.RawURLEncoding.DecodeString(metadata.CredentialID)
	if err != nil {
		return nil, fmt.Errorf("invalid fido2 credential id: %w", err)
	}
	salt, err := base64.RawURLEncoding.DecodeString(metadata.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid fido2 salt: %w", err)
	}
	cDevicePath := C.CString(devicePath)
	cRPID := C.CString(metadata.RPID)
	var cPIN *C.char
	if pin != "" {
		cPIN = C.CString(pin)
	}
	defer C.free(unsafe.Pointer(cDevicePath))
	defer C.free(unsafe.Pointer(cRPID))
	if cPIN != nil {
		defer C.free(unsafe.Pointer(cPIN))
	}

	var secret *C.uchar
	var secretLen C.size_t
	rc := C.knox_fido2_hmac_secret(
		cDevicePath,
		cRPID,
		cPIN,
		(*C.uchar)(unsafe.Pointer(&fido2ClientData[0])),
		C.size_t(len(fido2ClientData)),
		(*C.uchar)(unsafe.Pointer(&credentialID[0])),
		C.size_t(len(credentialID)),
		(*C.uchar)(unsafe.Pointer(&salt[0])),
		C.size_t(len(salt)),
		&secret,
		&secretLen,
	)
	if rc != C.FIDO_OK {
		return nil, fido2Error("derive fido2 hmac-secret", int(rc))
	}
	defer C.free(unsafe.Pointer(secret))
	if secretLen < 32 {
		return nil, fmt.Errorf("fido2 hmac-secret was too short: %d bytes", uint64(secretLen))
	}
	return C.GoBytes(unsafe.Pointer(secret), C.int(secretLen)), nil
}

func resolveFido2Device(device string) (string, error) {
	fido2InitOnce.Do(func() {
		C.fido_init(0)
	})
	device = strings.TrimSpace(device)
	if device != "" && device != "auto" {
		return device, nil
	}
	var path *C.char
	rc := C.knox_fido2_first_device_path(&path)
	if rc != C.FIDO_OK {
		return "", fido2Error("discover fido2 device", int(rc))
	}
	defer C.free(unsafe.Pointer(path))
	return C.GoString(path), nil
}

func loadFido2PIN(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	if err := validateAbsoluteCleanPath(path, "fido2 pin file"); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("failed to stat fido2 pin file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("fido2 pin file must not be a symlink")
	}
	if info.IsDir() {
		return "", errors.New("fido2 pin file path must be a regular file")
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return "", fmt.Errorf("fido2 pin file has insecure permissions %o (should be 0600)", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read fido2 pin file: %w", err)
	}
	pin := strings.TrimRight(string(data), "\r\n")
	if pin == "" {
		return "", errors.New("fido2 pin file is empty")
	}
	return pin, nil
}

func fido2Error(operation string, rc int) error {
	return fmt.Errorf("%s failed: %s", operation, C.GoString(C.knox_fido2_strerr(C.int(rc))))
}
