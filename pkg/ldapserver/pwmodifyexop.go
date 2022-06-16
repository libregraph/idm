package ldapserver

import (
	"errors"
	"log"
	"net"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

const pwmodOID = "1.3.6.1.4.1.4203.1.11.1"

const (
	TagReqIdentity = 0
	TagReqOldPW    = 1
	TagReqNewPW    = 2
	TagRespGenPW   = 0
)

func init() {
	RegisterExtendedOperation(pwmodOID, HandlePasswordModifyExOp)
}

func HandlePasswordModifyExOp(req *ber.Packet, boundDN string, server *Server, conn net.Conn) (*ber.Packet, error) {
	log.Printf("HandlePasswordModifyExOp")
	if boundDN == "" {
		return nil, ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("authentication required"))
	}

	pwReq, err := parsePasswordModifyExop(req)
	if err != nil {
		return nil, err
	}

	// If `UserIdentity` is empty, this is a request to update the bound user's own password
	if pwReq.UserIdentity == "" {
		pwReq.UserIdentity = boundDN
	}
	log.Printf("Modify password extended operation for user '%s'", pwReq.UserIdentity)
	return nil, nil
}

func parsePasswordModifyExop(req *ber.Packet) (*ldap.PasswordModifyRequest, error) {
	pwReq := ldap.PasswordModifyRequest{}

	// An absent (or empty) body of the request is valid. Translates into: "generate a new password for
	// for the current user"
	if req == nil {
		return &pwReq, nil
	}

	inner := ber.DecodePacket(req.Data.Bytes())
	if inner == nil {
		return &pwReq, nil
	}

	if len(inner.Children) > 3 {
		return nil, ldap.NewError(ldap.LDAPResultDecodingError, errors.New("invalid request"))
	}

	for _, kid := range inner.Children {
		if kid.ClassType != ber.ClassContext {
			return nil, ldap.NewError(ldap.LDAPResultDecodingError, errors.New("invalid request"))
		}
		switch kid.Tag {
		default:
			return nil, ldap.NewError(ldap.LDAPResultDecodingError, errors.New("invalid request"))
		case TagReqIdentity:
			pwReq.UserIdentity = kid.Data.String()
		case TagReqOldPW:
			pwReq.OldPassword = kid.Data.String()
		case TagReqNewPW:
			pwReq.NewPassword = kid.Data.String()
		}
	}
	return &pwReq, nil
}
