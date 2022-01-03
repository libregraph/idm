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
		t.Errorf("Deleting all values from Attribute failed")
	}

	mr.Changes = []ldap.Change{}
	mr.Delete("multivalue", []string{"value1"})
	e, err = ApplyModify(userEntry, mr)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	values = e.GetAttributeValues("multivalue")
	if len(values) != 1 || values[0] != "value2" {
		t.Errorf("Deleting a non-RDN Values from RDN Attribute failed")
	}
}

func TestApplyModifyAddValue(t *testing.T) {
	mr := &ldap.ModifyRequest{
		DN: userEntry.DN,
	}
	mr.Add("mail", []string{"other@example"})
	e, err := ApplyModify(userEntry, mr)
	if err != nil {
		t.Errorf(err.Error())
	}
	vals := e.GetAttributeValues("mail")
	if len(vals) != 2 {
		t.Errorf("Add attribute value failed")
	}

	mr.Changes = []ldap.Change{}
	mr.Add("newAttribute", []string{"value"})
	e, err = ApplyModify(userEntry, mr)
	if err != nil {
		t.Errorf(err.Error())
	}
	val := e.GetAttributeValue("newAttribute")
	if val != "value" {
		t.Errorf("Add attribute value failed")
	}
}

func TestApplyModifyReplace(t *testing.T) {
	mr := &ldap.ModifyRequest{
		DN: userEntry.DN,
	}
	mr.Replace("mail", []string{"other@example"})
	e, err := ApplyModify(userEntry, mr)
	if err != nil {
		t.Errorf(err.Error())
	}
	vals := e.GetAttributeValues("mail")
	if len(vals) != 1 || vals[0] != "other@example" {
		t.Errorf("Replace attribute value failed")
	}
}

func TestDropEntryAttribute(t *testing.T) {
	e := EntryDropAttribute(userEntry, "displayName")
	if len(e.GetEqualFoldAttributeValues("displayName")) != 0 {
		t.Errorf("Attribute does still exist after delete")
	}
	e = EntryDropAttribute(userEntry, "doesnotexist")
	if len(e.GetEqualFoldAttributeValues("doesnotexist")) != 0 {
		t.Errorf("Dropping non existing Attribute failed")
	}
	if len(e.GetEqualFoldAttributeValues("displayName")) != 1 {
		t.Errorf("Dropping non existing Attribute failed")
	}
}
