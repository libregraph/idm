package ldapserver

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestParseDeleteRequestIncomplete(t *testing.T) {
	inner := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationDelRequest, nil, "Delete Request")
	inner.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=test", "DN"))

	// improper Delete Request should error out
	_, err := parseDeleteRequest(inner)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
		t.Errorf("LDAP Delete Request without DN should give Protocol Error. Got:  %v", err)
	}

	// DelRequest with invalid DN should error out
	del := ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "value1", "Value")
	_, err = parseDeleteRequest(del)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
		t.Errorf("LDAP Delete Request with invalid DN should give Protocol Error. Got:  %v", err)
	}

	del = ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=value1,dc=example,dc=org", "Value")
	_, err = parseDeleteRequest(del)
	if err != nil {
		t.Errorf("valid LDAP Delete Request should succeed. Got:  %v", err)
	}

}
