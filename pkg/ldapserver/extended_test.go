package ldapserver

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func createExtEnvelope() *ber.Packet {
	mod := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "Test Extended Request")
	return mod
}

func TestParseExtendedRequest(t *testing.T) {
	mod := createExtEnvelope()
	_, err := parseExtendedRequest(mod)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultDecodingError) {
		t.Errorf("LDAP Extended Request without OID give Decoding Error. Got:  %v", err)
	}
	mod.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "0.1", "OID"))
	_, err = parseExtendedRequest(mod)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultDecodingError) {
		t.Errorf("LDAP Extended Request invalid OID type give Decoding Error. Got:  %v", err)
	}

	mod = createExtEnvelope()
	mod.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "0.1", "OID"))
	_, err = parseExtendedRequest(mod)
	if err != nil {
		t.Errorf("LDAP Extended Request with just OID should succeed")
	}
	mod.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 1, "0.1", "opaque"))
	_, err = parseExtendedRequest(mod)
	if err != nil {
		t.Errorf("LDAP Extended Request with just OID and body should succeed")
	}
	mod.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagObjectIdentifier, "0.1", "OID"))
	_, err = parseExtendedRequest(mod)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultDecodingError) {
		t.Errorf("LDAP Extended Request with excess data should fail with Decoding error")
	}

	mod = createExtEnvelope()
	mod.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "0.1", "OID"))
	_, err = parseExtendedRequest(mod)
	if err != nil {
		t.Errorf("LDAP Extended Request with just OID should succeed")
	}
	mod.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 42, "0.1", "opaque"))
	_, err = parseExtendedRequest(mod)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultDecodingError) {
		t.Errorf("LDAP Extended Request with invalid Body Tag should fail")
	}
}
