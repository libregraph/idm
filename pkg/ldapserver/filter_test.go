package ldapserver

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestServerFilterScope(t *testing.T) {
	type args struct {
		baseDN string
		scope  int
		entry  *ldap.Entry
	}
	tests := []struct {
		name  string
		args  args
		want  bool
		want1 LDAPResultCode
	}{
		{
			name: "Equal The baseND is lowercase BaseObject scope",
			args: args{
				baseDN: "uid=mariya,ou=users,o=libregraph-idm",
				scope:  0, // ScopeBaseObject
				entry:  ldap.NewEntry("uid=mariya,ou=users,o=libregraph-idm", nil),
			},
			want:  true,
			want1: ldap.LDAPResultSuccess,
		},
		{
			name: "Equal The baseND uid is capitalized BaseObject scope",
			args: args{
				baseDN: "uid=Mariya,ou=users,o=libregraph-idm",
				scope:  0, // ScopeBaseObject
				entry:  ldap.NewEntry("uid=mariya,ou=users,o=libregraph-idm", nil),
			},
			want:  true,
			want1: ldap.LDAPResultSuccess,
		},
		{
			name: "Equal The baseND parts are capitalized BaseObject scope",
			args: args{
				baseDN: "uid=Mariya,ou=Users,o=Libregraph-idm",
				scope:  0, // ScopeBaseObject
				entry:  ldap.NewEntry("uid=mariya,ou=users,o=libregraph-idm", nil),
			},
			want:  true,
			want1: ldap.LDAPResultSuccess,
		},
		{
			name: "Not equal The baseND parts are capitalized BaseObject scope",
			args: args{
				baseDN: "uid=Bob,ou=Users,o=Libregraph-idm",
				scope:  0, // ScopeBaseObject
				entry:  ldap.NewEntry("uid=mariya,ou=users,o=libregraph-idm", nil),
			},
			want:  false,
			want1: ldap.LDAPResultSuccess,
		},
		{
			name: "Equal The baseND is lowercase ScopeSingleLevel scope",
			args: args{
				baseDN: "ou=users,o=libregraph-idm",
				scope:  1, // ScopeSingleLevel
				entry:  ldap.NewEntry("uid=mariya,ou=users,o=libregraph-idm", nil),
			},
			want:  true,
			want1: ldap.LDAPResultSuccess,
		},
		{
			name: "Equal The baseND parts are capitalized ScopeSingleLevel scope",
			args: args{
				baseDN: "ou=Users,o=Libregraph-idm",
				scope:  1, // ScopeSingleLevel
				entry:  ldap.NewEntry("uid=mariya,ou=users,o=libregraph-idm", nil),
			},
			want:  true,
			want1: ldap.LDAPResultSuccess,
		},
		{
			name: "Not equal The baseND parts are capitalized ScopeSingleLevel scope",
			args: args{
				baseDN: "ou=User,o=Libregraph-idm",
				scope:  1, // ScopeSingleLevel
				entry:  ldap.NewEntry("uid=mariya,ou=users,o=libregraph-idm", nil),
			},
			want:  false,
			want1: ldap.LDAPResultSuccess,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := ServerFilterScope(tt.args.baseDN, tt.args.scope, tt.args.entry)
			if got != tt.want {
				t.Errorf("ServerFilterScope() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("ServerFilterScope() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
