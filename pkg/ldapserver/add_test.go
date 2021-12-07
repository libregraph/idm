package ldapserver

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestParseAddRequestIncomplete(t *testing.T) {
	inner := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationAddRequest, nil, "Add Request")
	inner.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=test", "DN"))

	// AddRequest without Attributes should error out
	_, err := parseAddRequest(inner)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
		t.Errorf("LDAP Add Request without Attributes should give Protocol Error. Got:  %v", err)
	}

	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	inner.AppendChild(attributes)
	_, err = parseAddRequest(inner)
	if err != nil {
		t.Errorf("Valid LDAP Request should succeed. Got: %v", err)
	}

	extraElement := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Extra Stuff")
	inner.AppendChild(extraElement)
	// AddRequest with and extra Element  should error out
	_, err = parseAddRequest(inner)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
		t.Errorf("LDAP Add Request extra elements should give Protocol Error. Got:  %v", err)
	}
}

func TestParseAddRequestInvalidDN(t *testing.T) {
	inner := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationAddRequest, nil, "Add Request")
	inner.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "invalidDN", "DN"))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	inner.AppendChild(attributes)

	// AddRequest with invalid DN should error out
	_, err := parseAddRequest(inner)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
		t.Errorf("LDAP Add Request with invalid DN should give Protocol Error. Got:  %v", err)
	}
}

func TestParseAttributeList(t *testing.T) {
	// Construct AttributeList with invalid BER tag
	attributes := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Attributes")
	_, err := parseAttributeList(attributes)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
		t.Errorf("Invalid Attribute list should give Protocol error. Got: %v", err)
	}

	attributes = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "AttributeType"))
	attributes.AppendChild(attribute)

	_, err = parseAttributeList(attributes)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultProtocolError) {
		t.Errorf("Missing Attribute value should give Protocol error. Got: %v", err)
	}

	attributes = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attribute = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "AttributeType"))
	values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
	values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "value1", "Value"))
	values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "value2", "Value"))
	attribute.AppendChild(values)
	attributes.AppendChild(attribute)
	_, err = parseAttributeList(attributes)
	if err != nil {
		t.Errorf("Valid Attribute List should succeed. Got: %v", err)
	}

}
