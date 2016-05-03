package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"time"

	"testing"

	"github.com/pinterest/knox"
)

func TestUserCanAccess(t *testing.T) {
	u := NewUser("test", []string{"returntrue"})
	a1 := knox.Access{ID: "test", AccessType: knox.Write, Type: knox.User}
	a2 := knox.Access{ID: "returnfalse", AccessType: knox.Admin, Type: knox.UserGroup}
	a3 := knox.Access{ID: "returntrue", AccessType: knox.Admin, Type: knox.UserGroup}

	acl1 := knox.ACL([]knox.Access{a1})
	if !u.CanAccess(acl1, knox.Write) {
		t.Error("user can't access user permission matching id")
	}
	if u.CanAccess(acl1, knox.Admin) {
		t.Error("user can access user permission with increased access type")
	}

	acl2 := knox.ACL([]knox.Access{a2})
	if u.CanAccess(acl2, knox.Write) {
		t.Error("user can access group they are not in")
	}

	acl3 := knox.ACL([]knox.Access{a3})
	if !u.CanAccess(acl3, knox.Read) {
		t.Error("user can't access group they are in")
	}

	acl4 := knox.ACL([]knox.Access{a2, a3, a1})
	if !u.CanAccess(acl4, knox.Admin) {
		t.Error("user can't access group they are in with multiple members")
	}

	acl5 := knox.ACL([]knox.Access{})
	if u.CanAccess(acl5, knox.Admin) {
		t.Error("user can access empty ACL")
	}
}
func TestMachineCanAccess(t *testing.T) {
	u := machine("test001")
	a1 := knox.Access{ID: "test001", AccessType: knox.Write, Type: knox.Machine}
	a2 := knox.Access{ID: "doesnotmatch", AccessType: knox.Admin, Type: knox.MachinePrefix}
	a3 := knox.Access{ID: "test", AccessType: knox.Admin, Type: knox.MachinePrefix}

	acl1 := knox.ACL([]knox.Access{a1})
	if !u.CanAccess(acl1, knox.Write) {
		t.Error("machine can't access user permission matching id")
	}
	if u.CanAccess(acl1, knox.Admin) {
		t.Error("machine can access user permission with increased access type")
	}

	acl2 := knox.ACL([]knox.Access{a2})
	if u.CanAccess(acl2, knox.Write) {
		t.Error("machine can access group they are not in")
	}

	acl3 := knox.ACL([]knox.Access{a3})
	if !u.CanAccess(acl3, knox.Read) {
		t.Error("machine can't access group they are in")
	}

	acl4 := knox.ACL([]knox.Access{a2, a3, a1})
	if !u.CanAccess(acl4, knox.Admin) {
		t.Error("machine can't access group they are in with multiple members")
	}

	acl5 := knox.ACL([]knox.Access{})
	if u.CanAccess(acl5, knox.Admin) {
		t.Error("machine can access empty ACL")
	}
}

const caCert = `-----BEGIN CERTIFICATE-----
MIICOjCCAeCgAwIBAgIUIKkBZQbtx8rVaWIOhpabkqZSqecwCgYIKoZIzj0EAwIw
aTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzAeFw0xNjA0MTMwMDQ2MDBaFw0yMTA0MTIwMDQ2MDBaMGkxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJh
bmNpc2NvMR8wHQYDVQQKExZJbnRlcm5ldCBXaWRnZXRzLCBJbmMuMQwwCgYDVQQL
EwNXV1cwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT2bdxWXCY2y7YwFdDqgBOG
xMk66tC6L2CXBlSue9/GNypv771VfRFf7RtNa/3/pTLEVJZaj25sOXCJaNeFX9GE
o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4E
FgQUHeijCT+fV2y15OFqaV+BuROvrG4wHwYDVR0jBBgwFoAUHeijCT+fV2y15OFq
aV+BuROvrG4wCgYIKoZIzj0EAwIDSAAwRQIgZpgo1bmCAdSaVCqJKDmMKfui2dT/
3ucYcCZi9dUZjtMCIQC/d1se0XhhZ8eRfqzf0Uj0jHvan4opB0aD5CgSVlct0w==
-----END CERTIFICATE-----`

// clientCertB64 is a base64 encoded cert (inner contents of a CERTIFICATE pem block)
const clientCertB64 = `MIICjzCCAjSgAwIBAgIUUOdxnpGiNZhsB0AySQMJ+Lx5WqEwCgYIKoZIzj0EAwIw
aTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xHzAdBgNVBAoTFkludGVybmV0IFdpZGdldHMsIEluYy4xDDAK
BgNVBAsTA1dXVzAeFw0xNjA0MTMwMDQ5MDBaFw0xNzA0MTMwMDQ5MDBaMIGDMQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZy
YW5jaXNjbzEWMBQGA1UEChMNUGludGVyZXN0IEluYzETMBEGA1UECxMKcGluMjIw
LmNvbTEaMBgGA1UEAxMRZGV2LWRldmlubHVuZGJlcmcwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAATntqtFfYd8qDNzhRgbi3CMgRHnz92Vt70nmJntO6XIk1tHyP9b
k4aJe7KplZG8Fc56lB4Y+kE+6INE/6OkYqxKo4GeMIGbMA4GA1UdDwEB/wQEAwIF
oDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAd
BgNVHQ4EFgQUKRAflMKxR43xkv9w+yN7raOGFpAwHwYDVR0jBBgwFoAUHeijCT+f
V2y15OFqaV+BuROvrG4wHAYDVR0RBBUwE4IRZGV2LWRldmlubHVuZGJlcmcwCgYI
KoZIzj0EAwIDSQAwRgIhAIRd87po8pVE1CFSSM/uPwHFPg3gWlC1Pvl5h5e+2ogf
AiEA/GIpOpaFQbGSs42rKugOBngKtF0fuRAo2r4vMyL559A=`

func TestMTLSSuccess(t *testing.T) {
	hostname := "dev-devinlundberg"
	expected := "dev-devinlundberg"
	req, err := http.NewRequest("GET", "http://localhost/", nil)
	req.Header.Add("Authorization", "0t"+hostname)
	req.RemoteAddr = "0.0.0.0:23423"
	certBytes := make([]byte, base64.StdEncoding.DecodedLen(len(clientCertB64)))
	n, err := base64.StdEncoding.Decode(certBytes, []byte(clientCertB64))
	if err != nil {
		t.Fatal(err.Error())
	}
	c, err := x509.ParseCertificate(certBytes[:n])
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{c},
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM([]byte(caCert))
	a := MTLSAuthProvider{
		CAs:  caPool,
		time: func() time.Time { return time.Date(2016, time.April, 22, 11, 0, 0, 0, time.UTC) },
	}
	p, err := a.Authenticate(hostname, req)

	if err != nil {
		t.Fatal(err.Error())
	}
	if p != machine(expected) {
		t.Fatal("Hostnames don't match got: " + p.GetID())
	}
}

func TestMTLSBadTime(t *testing.T) {
	hostname := "dev-devinlundberg"
	req, err := http.NewRequest("GET", "http://localhost/", nil)
	req.Header.Add("Authorization", "0t"+hostname)
	req.RemoteAddr = "0.0.0.0:23423"
	certBytes := make([]byte, base64.StdEncoding.DecodedLen(len(clientCertB64)))
	n, err := base64.StdEncoding.Decode(certBytes, []byte(clientCertB64))
	if err != nil {
		t.Fatal(err.Error())
	}
	c, err := x509.ParseCertificate(certBytes[:n])
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{c},
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM([]byte(caCert))
	a := MTLSAuthProvider{
		CAs:  caPool,
		time: func() time.Time { return time.Date(2018, time.April, 22, 11, 0, 0, 0, time.UTC) },
	}
	_, err = a.Authenticate(hostname, req)

	if err == nil {
		t.Fatal("Call should fail due to expired cert")
	}
}

func TestMTLSNoCA(t *testing.T) {
	hostname := "dev-devinlundberg"
	req, err := http.NewRequest("GET", "http://localhost/", nil)
	req.Header.Add("Authorization", "0t"+hostname)
	req.RemoteAddr = "0.0.0.0:23423"
	certBytes := make([]byte, base64.StdEncoding.DecodedLen(len(clientCertB64)))
	n, err := base64.StdEncoding.Decode(certBytes, []byte(clientCertB64))
	if err != nil {
		t.Fatal(err.Error())
	}
	c, err := x509.ParseCertificate(certBytes[:n])
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{c},
	}

	a := MTLSAuthProvider{
		CAs:  x509.NewCertPool(),
		time: func() time.Time { return time.Date(2016, time.April, 22, 11, 0, 0, 0, time.UTC) },
	}
	_, err = a.Authenticate(hostname, req)

	if err == nil {
		t.Fatal("There is no matching CA for this cert")
	}
}

func TestMTLSBadHostname(t *testing.T) {
	hostname := "BadHostname"
	req, err := http.NewRequest("GET", "http://localhost/", nil)
	req.Header.Add("Authorization", "0t"+hostname)
	req.RemoteAddr = "0.0.0.0:23423"
	certBytes := make([]byte, base64.StdEncoding.DecodedLen(len(clientCertB64)))
	n, err := base64.StdEncoding.Decode(certBytes, []byte(clientCertB64))
	if err != nil {
		t.Fatal(err.Error())
	}
	c, err := x509.ParseCertificate(certBytes[:n])
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{c},
	}

	a := MTLSAuthProvider{
		CAs:  x509.NewCertPool(),
		time: func() time.Time { return time.Date(2016, time.April, 22, 11, 0, 0, 0, time.UTC) },
	}
	_, err = a.Authenticate(hostname, req)

	if err == nil {
		t.Fatal("hostname should not match")
	}

}

func TestGetUser(t *testing.T) {
	token := "valid"
	a := MockGitHubProvider()
	principal, err := a.Authenticate(token, nil)
	if err != nil {
		t.Error(err.Error())
	}
	u, ok := principal.(user)
	if !ok {
		t.Error("unexpected type of principal")
	}
	if u.GetID() != "testuser" {
		t.Error("unexpected principal")
	}
	if !u.inGroup("testgroup") {
		t.Error("User should be in testgroup")
	}
	if u.inGroup("nottestgroup") {
		t.Error("User should not be in nottestgroup")
	}
}

func TestGetInvalidUser(t *testing.T) {
	token := "notvalid"
	a := MockGitHubProvider()
	_, err := a.Authenticate(token, nil)
	if err == nil {
		t.Error("Expected Error with invalid token")
	}
}
