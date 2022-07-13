package ldapdn

import (
	"testing"
)

func TestParseNormalize(t *testing.T) {
	tests := map[string]string{
		"uid=Test,ou=test":            "uid=test,ou=test",
		"uid=rDN1+cn=rDN2,ou=test":    "uid=rdn1+cn=rdn2,ou=test",
		"uid=Test\\+withplus,ou=test": "uid=test\\+withplus,ou=test",
		"uid=Test\\2bTest,ou=test":    "uid=test\\+test,ou=test",
		"uid=Test\\00test,ou=teSt":    "uid=test\\00test,ou=test",
	}

	for in, out := range tests {
		res, err := ParseNormalize(in)
		if err != nil {
			t.Errorf("Unexpected err: %s", err)
		} else if res != out {
			t.Errorf("Expected %s got %s", out, res)
		}
	}
}
