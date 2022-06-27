package ldapserver

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func createPwExopPacket() *ber.Packet {
	return ber.Encode(ber.ClassContext, ber.TypePrimitive, 1, nil, "Password Exop Request")
}
func TestParsePasswordModifyExop(t *testing.T) {
	pwExop, err := parsePasswordModifyExop(nil)
	if err != nil {
		t.Errorf("Expected success when request does not contain body")
	}
	if pwExop.UserIdentity != "" || pwExop.OldPassword != "" || pwExop.NewPassword != "" {
		t.Errorf("Expected zero values Exop Request empty request body")
	}

	// Empty Request body
	pkt := createPwExopPacket()
	pwExop, err = parsePasswordModifyExop(pkt)
	if err != nil {
		t.Errorf("Expected success for empty request body. Got: %s", err)
	} else if pwExop.UserIdentity != "" || pwExop.OldPassword != "" || pwExop.NewPassword != "" {
		t.Errorf("Expected zero values Exop Request empty request body")
	}

	// Empty Sequence in Request body
	pkt.AppendChild(ber.NewSequence("Password Exop Request Body"))
	pwExop, err = parsePasswordModifyExop(pkt)
	if err != nil {
		t.Errorf("Expected success for empty request body. Got: %s", err)
	} else if pwExop.UserIdentity != "" || pwExop.OldPassword != "" || pwExop.NewPassword != "" {
		t.Errorf("Expected zero values Exop Request empty request body")
	}

	body := ber.NewSequence("Password Exop Request Body")
	body.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "identity", "UserIdentity"))
	pkt = createPwExopPacket()
	pkt.AppendChild(body)
	pwExop, err = parsePasswordModifyExop(pkt)
	switch {
	case err != nil:
		t.Errorf("Expected success for request with	just UserIdentity present. Got: %s", err)
	case pwExop.UserIdentity != "identity":
		t.Errorf("Expected UserIdentity to be present in request body")
	case pwExop.OldPassword != "" || pwExop.NewPassword != "":
		t.Errorf("Expected zero values Exop Request empty request body")
	}

	body = ber.NewSequence("Password Exop Request Body")
	body.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 1, "oldpw", "OldPassword"))
	pkt = createPwExopPacket()
	pkt.AppendChild(body)
	pwExop, err = parsePasswordModifyExop(pkt)
	switch {
	case err != nil:
		t.Errorf("Expected success for request with	just OldPassword present. Got: %s", err)
	case pwExop.OldPassword != "oldpw":
		t.Errorf("Expected OldPassword to be present in request body")
	case pwExop.UserIdentity != "" || pwExop.NewPassword != "":
		t.Errorf("Expected zero values Exop Request empty request body")
	}

	body = ber.NewSequence("Password Exop Request Body")
	body.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 2, "newpw", "NewPassword"))
	pkt = createPwExopPacket()
	pkt.AppendChild(body)
	pwExop, err = parsePasswordModifyExop(pkt)
	switch {
	case err != nil:
		t.Errorf("Expected success for request with	just NewPassword present. Got: %s", err)
	case pwExop.NewPassword != "newpw":
		t.Errorf("Expected NewPassword to be present in request body")
	case pwExop.UserIdentity != "" || pwExop.OldPassword != "":
		t.Errorf("Expected zero values Exop Request empty request body")
	}

	body = ber.NewSequence("Password Exop Request Body")
	body.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "identity", "UserIdentity"))
	body.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 1, "oldpw", "OldPassword"))
	body.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 2, "newpw", "NewPassword"))
	pkt = createPwExopPacket()
	pkt.AppendChild(body)
	pwExop, err = parsePasswordModifyExop(pkt)
	switch {
	case err != nil:
		t.Errorf("Expected success for request with all fields present. Got: %s", err)
	case pwExop.UserIdentity != "identity":
		t.Errorf("Expected UserIdentity to be present in request body")
	case pwExop.OldPassword != "oldpw":
		t.Errorf("Expected OldPassword to be present in request body")
	case pwExop.NewPassword != "newpw":
		t.Errorf("Expected NewPassword to be present in request body")
	}
}
