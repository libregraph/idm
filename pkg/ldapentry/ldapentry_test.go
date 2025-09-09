package ldapentry

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

var userEntry = ldap.NewEntry("uid=user,ou=sub,o=base",
	map[string][]string{
		"uid":         {"user"},
		"displayname": {"DisplayName"},
		"mail":        {"user@example"},
		"multivalue":  {"value1", "value2"},
		"entryuuid":   {"abcd-defg"},
	})

func TestApplyModifyWrongDN(t *testing.T) {
	mr := ldap.ModifyRequest{
		DN: "uid=wrongdn",
	}

	_, err := ApplyModify(userEntry, &mr)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
		t.Errorf("Error %v", err)
	}
}

func TestApplyModifyDelRDN(t *testing.T) {
	mr := &ldap.ModifyRequest{
		DN: userEntry.DN,
	}
	mr.Delete("uid", []string{})
	_, err := ApplyModify(userEntry, mr)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultNotAllowedOnRDN) {
		t.Errorf("Error %v", err)
	}

	mr.Changes = []ldap.Change{}
	mr.Delete("uid", []string{"user"})
	_, err = ApplyModify(userEntry, mr)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultNotAllowedOnRDN) {
		t.Errorf("Error %v", err)
	}

	userEntry1 := ldap.NewEntry("uid=user,ou=sub,o=base",
		map[string][]string{
			"uid":         {"user", "user1"},
			"displayname": {"DisplayName"},
			"mail":        {"user@example"},
			"entryuuid":   {"abcd-defg"},
		})
	mr.Changes = []ldap.Change{}
	mr.Delete("uid", []string{"user1"})
	e, err := ApplyModify(userEntry1, mr)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	values := e.GetAttributeValues("uid")
	if len(values) != 1 || values[0] != "user" {
		t.Errorf("Deleting a non-RDN Values from RDN Attribute failed")
	}
}

func TestApplyModifyDelete(t *testing.T) {
	mr := &ldap.ModifyRequest{
		DN: userEntry.DN,
	}
	mr.Delete("displayName", []string{})
	e, err := ApplyModify(userEntry, mr)
	if err != nil {
		t.Errorf("Error %v", err)
	}
	values := e.GetAttributeValues("displayName")
	if len(values) != 0 {
		t.Error("Deleting all values from Attribute failed")
	}

	mr.Changes = []ldap.Change{}
	mr.Delete("multivalue", []string{"value1"})
	e, err = ApplyModify(userEntry, mr)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	values = e.GetAttributeValues("multivalue")
	if len(values) != 1 || values[0] != "value2" {
		t.Error("Deleting a non-RDN Values from RDN Attribute failed")
	}
}

func TestApplyModifyAddValue(t *testing.T) {
	mr := &ldap.ModifyRequest{
		DN: userEntry.DN,
	}
	mr.Add("mail", []string{"other@example"})
	e, err := ApplyModify(userEntry, mr)
	if err != nil {
		t.Error(err.Error())
	}
	vals := e.GetAttributeValues("mail")
	if len(vals) != 2 {
		t.Error("Add attribute value failed")
	}

	mr.Changes = []ldap.Change{}
	mr.Add("newAttribute", []string{"value"})
	e, err = ApplyModify(userEntry, mr)
	if err != nil {
		t.Error(err.Error())
	}
	val := e.GetAttributeValue("newAttribute")
	if val != "value" {
		t.Error("Add attribute value failed")
	}
}

func TestApplyModifyReplace(t *testing.T) {
	mr := &ldap.ModifyRequest{
		DN: userEntry.DN,
	}
	mr.Replace("mail", []string{"other@example"})
	e, err := ApplyModify(userEntry, mr)
	if err != nil {
		t.Error(err.Error())
	}
	vals := e.GetAttributeValues("mail")
	if len(vals) != 1 || vals[0] != "other@example" {
		t.Error("Replace attribute value failed")
	}
}

func TestApplyModifyReplaceRDN(t *testing.T) {
	mr := &ldap.ModifyRequest{
		DN: userEntry.DN,
	}

	// Replacing the RDN value should fail
	mr.Replace("uid", []string{"otheruser"})
	_, err := ApplyModify(userEntry, mr)
	if err == nil || !ldap.IsErrorWithCode(err, ldap.LDAPResultNotAllowedOnRDN) {
		t.Errorf("Error %v", err)
	}

	// Replacing if the RDN value stays present should succeed
	mr = &ldap.ModifyRequest{
		DN: userEntry.DN,
	}
	mr.Replace("uid", []string{"user", "otheruser"})
	e, err := ApplyModify(userEntry, mr)
	if err != nil {
		t.Error(err.Error())
	}
	vals := e.GetAttributeValues("uid")
	if len(vals) != 2 {
		t.Error("Unexpected number of values after replace")
	}

	for _, v := range []string{"user", "otheruser"} {
		if vals[0] != v && vals[1] != v {
			t.Errorf("Value %s missing after replace", v)
		}
	}
}
