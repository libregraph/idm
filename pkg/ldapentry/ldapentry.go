package ldapentry

import (
	"github.com/go-ldap/ldap/v3"
)

func EntryFromAddRequest(add *ldap.AddRequest) *ldap.Entry {
	attrs := map[string][]string{}

	for _, a := range add.Attributes {
		attrs[a.Type] = a.Vals
	}
	return ldap.NewEntry(add.DN, attrs)
}
