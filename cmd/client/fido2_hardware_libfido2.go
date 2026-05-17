//go:build libfido2 && cgo

package main

/*
#cgo pkg-config: libfido2
#include <stdlib.h>
#include <string.h>
#include <fido.h>

typedef struct {
	unsigned char *ptr;
	size_t len;
} knox_fido2_buf;

enum {
	KNOX_FIDO2_ERR_ALLOC = -1,
	KNOX_FIDO2_ERR_DEVICE = -2,
	KNOX_FIDO2_ERR_RESULT = -3,
};

static int knox_fido2_copy_buf(const unsigned char *src, size_t len, knox_fido2_buf *out) {
	out->ptr = NULL;
	out->len = 0;
	if (len == 0) {
		return FIDO_OK;
	}
	if (src == NULL) {
		return KNOX_FIDO2_ERR_RESULT;
	}
	out->ptr = malloc(len);
	if (out->ptr == NULL) {
		return KNOX_FIDO2_ERR_ALLOC;
	}
	memcpy(out->ptr, src, len);
	out->len = len;
	return FIDO_OK;
}

static void knox_fido2_free_buf(knox_fido2_buf *buf) {
	if (buf != NULL && buf->ptr != NULL) {
		free(buf->ptr);
		buf->ptr = NULL;
		buf->len = 0;
	}
}

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

static int knox_fido2_make_webauthn_cred(
	const char *device_path,
	const char *rp_id,
	const char *rp_name,
	const char *pin,
	const unsigned char *client_data_hash,
	size_t client_data_hash_len,
	const unsigned char *user_id,
	size_t user_id_len,
	const char *user_name,
	const char *display_name,
	knox_fido2_buf *credential_id,
	knox_fido2_buf *authdata,
	int *failed_step
) {
	fido_dev_t *dev = NULL;
	fido_cred_t *cred = NULL;
	int rc = FIDO_OK;

	dev = fido_dev_new();
	cred = fido_cred_new();
	if (dev == NULL || cred == NULL) {
		rc = KNOX_FIDO2_ERR_ALLOC;
		goto out;
	}
	*failed_step = 1;
	if ((rc = fido_dev_open(dev, device_path)) != FIDO_OK) {
		goto out;
	}
	(void)fido_dev_set_timeout(dev, 60000);
	*failed_step = 2;
	if ((rc = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK) {
		goto out;
	}
	*failed_step = 3;
	if ((rc = fido_cred_set_clientdata_hash(cred, client_data_hash, client_data_hash_len)) != FIDO_OK) {
		goto out;
	}
	*failed_step = 4;
	if ((rc = fido_cred_set_rp(cred, rp_id, rp_name)) != FIDO_OK) {
		goto out;
	}
	*failed_step = 5;
	if ((rc = fido_cred_set_user(cred, user_id, user_id_len, user_name, display_name, NULL)) != FIDO_OK) {
		goto out;
	}
	*failed_step = 6;
	if ((rc = fido_cred_set_rk(cred, FIDO_OPT_FALSE)) != FIDO_OK) {
		goto out;
	}
	*failed_step = 7;
	if ((rc = fido_cred_set_uv(cred, FIDO_OPT_FALSE)) != FIDO_OK) {
		goto out;
	}
	*failed_step = 8;
	if ((rc = fido_dev_make_cred(dev, cred, pin)) != FIDO_OK) {
		goto out;
	}
	*failed_step = 9;
	if ((rc = knox_fido2_copy_buf(fido_cred_id_ptr(cred), fido_cred_id_len(cred), credential_id)) != FIDO_OK) {
		goto out;
	}
	*failed_step = 10;
	rc = knox_fido2_copy_buf(fido_cred_authdata_raw_ptr(cred), fido_cred_authdata_raw_len(cred), authdata);

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

static int knox_fido2_get_webauthn_assertion(
	const char *device_path,
	const char *rp_id,
	const char *pin,
	const unsigned char *client_data_hash,
	size_t client_data_hash_len,
	const unsigned char *credential_id,
	size_t credential_id_len,
	knox_fido2_buf *authdata,
	knox_fido2_buf *signature,
	knox_fido2_buf *user_id
) {
	fido_dev_t *dev = NULL;
	fido_assert_t *assert = NULL;
	int rc = FIDO_OK;

	dev = fido_dev_new();
	assert = fido_assert_new();
	if (dev == NULL || assert == NULL) {
		rc = KNOX_FIDO2_ERR_ALLOC;
		goto out;
	}
	if ((rc = fido_dev_open(dev, device_path)) != FIDO_OK) {
		goto out;
	}
	(void)fido_dev_set_timeout(dev, 60000);
	if ((rc = fido_assert_set_clientdata_hash(assert, client_data_hash, client_data_hash_len)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_assert_set_rp(assert, rp_id)) != FIDO_OK) {
		goto out;
	}
	if ((rc = fido_assert_allow_cred(assert, credential_id, credential_id_len)) != FIDO_OK) {
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
	if ((rc = knox_fido2_copy_buf(fido_assert_authdata_raw_ptr(assert, 0), fido_assert_authdata_raw_len(assert, 0), authdata)) != FIDO_OK) {
		goto out;
	}
	if ((rc = knox_fido2_copy_buf(fido_assert_sig_ptr(assert, 0), fido_assert_sig_len(assert, 0), signature)) != FIDO_OK) {
		goto out;
	}
	rc = knox_fido2_copy_buf(fido_assert_user_id_ptr(assert, 0), fido_assert_user_id_len(assert, 0), user_id);

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
	case KNOX_FIDO2_ERR_RESULT:
		return "FIDO2 device returned no usable result";
	default:
		return fido_strerr(rc);
	}
}
*/
import "C"

import (
	"crypto/sha256"
	"fmt"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
)

type fido2HardwareCredential struct {
	CredentialID []byte
	AuthData     []byte
}

type fido2HardwareAssertion struct {
	AuthData  []byte
	Signature []byte
}

func fido2FirstDevicePath() (string, error) {
	C.fido_init(0)
	var cPath *C.char
	rc := C.knox_fido2_first_device_path(&cPath)
	if rc != C.FIDO_OK {
		return "", fido2Error("discover FIDO2 device", rc)
	}
	defer C.free(unsafe.Pointer(cPath))
	return C.GoString(cPath), nil
}

func fido2MakeCredential(devicePath, rpID, rpName, pin string, userID []byte, userName, displayName string, clientData []byte) (fido2HardwareCredential, error) {
	C.fido_init(0)
	clientDataHash := sha256.Sum256(clientData)
	cDevice := C.CString(devicePath)
	cRPID := C.CString(rpID)
	cRPName := C.CString(rpName)
	cUserName := C.CString(userName)
	cDisplayName := C.CString(displayName)
	var cPIN *C.char
	if pin != "" {
		cPIN = C.CString(pin)
	}
	defer C.free(unsafe.Pointer(cDevice))
	defer C.free(unsafe.Pointer(cRPID))
	defer C.free(unsafe.Pointer(cRPName))
	defer C.free(unsafe.Pointer(cUserName))
	defer C.free(unsafe.Pointer(cDisplayName))
	if cPIN != nil {
		defer C.free(unsafe.Pointer(cPIN))
	}

	var credentialID C.knox_fido2_buf
	var authData C.knox_fido2_buf
	var failedStep C.int
	rc := C.knox_fido2_make_webauthn_cred(
		cDevice,
		cRPID,
		cRPName,
		cPIN,
		(*C.uchar)(unsafe.Pointer(&clientDataHash[0])),
		C.size_t(len(clientDataHash)),
		(*C.uchar)(unsafe.Pointer(&userID[0])),
		C.size_t(len(userID)),
		cUserName,
		cDisplayName,
		&credentialID,
		&authData,
		&failedStep,
	)
	if rc != C.FIDO_OK {
		return fido2HardwareCredential{}, fmt.Errorf("%w (step %d)", fido2Error("make FIDO2 credential", rc), int(failedStep))
	}
	defer C.knox_fido2_free_buf(&credentialID)
	defer C.knox_fido2_free_buf(&authData)

	return fido2HardwareCredential{
		CredentialID: C.GoBytes(unsafe.Pointer(credentialID.ptr), C.int(credentialID.len)),
		AuthData:     C.GoBytes(unsafe.Pointer(authData.ptr), C.int(authData.len)),
	}, nil
}

func fido2GetAssertion(devicePath, rpID, pin string, credentialID []byte, clientData []byte) (fido2HardwareAssertion, error) {
	C.fido_init(0)
	clientDataHash := sha256.Sum256(clientData)
	cDevice := C.CString(devicePath)
	cRPID := C.CString(rpID)
	var cPIN *C.char
	if pin != "" {
		cPIN = C.CString(pin)
	}
	defer C.free(unsafe.Pointer(cDevice))
	defer C.free(unsafe.Pointer(cRPID))
	if cPIN != nil {
		defer C.free(unsafe.Pointer(cPIN))
	}

	var authData C.knox_fido2_buf
	var signature C.knox_fido2_buf
	var returnedUserID C.knox_fido2_buf
	rc := C.knox_fido2_get_webauthn_assertion(
		cDevice,
		cRPID,
		cPIN,
		(*C.uchar)(unsafe.Pointer(&clientDataHash[0])),
		C.size_t(len(clientDataHash)),
		(*C.uchar)(unsafe.Pointer(&credentialID[0])),
		C.size_t(len(credentialID)),
		&authData,
		&signature,
		&returnedUserID,
	)
	if rc != C.FIDO_OK {
		return fido2HardwareAssertion{}, fido2Error("get FIDO2 assertion", rc)
	}
	defer C.knox_fido2_free_buf(&authData)
	defer C.knox_fido2_free_buf(&signature)
	defer C.knox_fido2_free_buf(&returnedUserID)

	return fido2HardwareAssertion{
		AuthData:  C.GoBytes(unsafe.Pointer(authData.ptr), C.int(authData.len)),
		Signature: C.GoBytes(unsafe.Pointer(signature.ptr), C.int(signature.len)),
	}, nil
}

func fido2NoneAttestationObject(authData []byte) ([]byte, error) {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create CBOR encoder: %w", err)
	}
	return enc.Marshal(map[string]any{
		"fmt":      "none",
		"authData": authData,
		"attStmt":  map[string]any{},
	})
}

func fido2Error(operation string, rc C.int) error {
	return fmt.Errorf("%s: %s", operation, C.GoString(C.knox_fido2_strerr(rc)))
}
