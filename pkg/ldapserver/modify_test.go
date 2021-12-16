package ldapserver

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func createModEnvelope() *ber.Packet {
	mod := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationModifyRequest, nil, "Modify Request")
	mod.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=test", "DN"))
	return mod
}

func createChange(changeType uint64) *ber.Packet {
	change := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Change")
	change.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, changeType, "Operation"))
	attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "AttributeType"))
	change.AppendChild(attribute)
	return change
}

func TestParseModifyRequest(t *testing.T) {
	mod := createModEnvelope()
	// Modify with Changes should error out
	_, err := parseModifyRequest(mod)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
		t.Errorf("LDAP Modify Request without changes sequence should give Protocol Error. Got:  %v", err)
	}

	// Modify with an empty Changes Sequence should succeed
	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")
	mod.AppendChild(changes)
	_, err = parseModifyRequest(mod)
	if err != nil {
		t.Errorf("Valid LDAP Request should succeed. Got: %v", err)
	}

	extraElement := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Extra Stuff")
	mod.AppendChild(extraElement)
	// Modify with an extra Element  should error out
	_, err = parseModifyRequest(mod)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
		t.Errorf("LDAP Modify Request with extra elements should give Protocol Error. Got:  %v", err)
	}
}

func TestParseModifyRequestInvalidOp(t *testing.T) {
	mod := createModEnvelope()

	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")
	changes.AppendChild(createChange(42))
	mod.AppendChild(changes)

	_, err := parseModifyRequest(mod)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultDecodingError) {
		t.Errorf("LDAP Modify Requset with wrong change type should give protocol error %v", err)
	}
}

func TestParseModifyRequestDelete(t *testing.T) {
	mod := createModEnvelope()

	changes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Changes")
	changes.AppendChild(createChange(ldap.DeleteAttribute))
	mod.AppendChild(changes)

	_, err := parseModifyRequest(mod)
	if err != nil {
		t.Errorf("Valid LDAP Modify Request	 should succeed. Got: '%v'", err)
	}
}
