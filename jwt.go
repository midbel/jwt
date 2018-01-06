//Package jwt provides a basic implementation of JSON Web Token as described in
//RFC 7519.
//
//This package is not yet fully compliant with the RFC since it does
//yet provide the RS256 algorithm.
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const JWT = "jwt"

var std = base64.StdEncoding.WithPadding(base64.NoPadding)

//Common errors type
var (
	//ErrBadSignature is returned when the signature of token does not match the
	//expected signature generated with the secret key
	ErrBadSignature = errors.New("bad signature")

	//ErrBadSecret is returned when an empty secret key is given.
	ErrBadSecret = errors.New("bad secret key")

	//ErrMalFormed is returned when the token does not have the expected format
	//as described in the RFC.
	ErrMalFormed = errors.New("malformed token")

	//ErrInvalid is returned when the token hasn't the good issuer or when it has
	//expired or when the issue at is after the expiration time. ErrInvalid is
	//also returned when the payload can not be unmarshaled from the token.
	ErrInvalid = errors.New("invalid token")
)

//Signer is the interface type that provides the methods to generate JWT (by
//signing any payload) and to verfiy them.
type Signer interface {
	//Sign generate the payload for the given token. It returns on error if the
	//payload can not be marshalled in JSON.
	Sign(interface{}) (string, error)

	//Verify check the given token from the Signer settings and unmarshal the
	//payload. It gives an error if the token is invalid or malformed.
	Verify(string, interface{}) error
}

type jose struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func (j *jose) UnmarshalJSON(bs []byte) error {
	v := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{}
	if err := json.Unmarshal(bs, &v); err != nil {
		return err
	}
	if !(v.Alg == "HS256" || v.Typ == JWT) {
		return ErrMalFormed
	}
	j.Alg, j.Typ = v.Alg, v.Typ
	return nil
}

type claims struct {
	Payload interface{} `json:"payload"`
	Issuer  string      `json:"iss,omitempty"`
	Jid     string      `json:"jti,omitempty"`
	Created *time.Time  `json:"iat,omitempty"`
	Expired *time.Time  `json:"exp,omitempty"`
}

type none struct {
	TTL    int
	Issuer string
}

func (n *none) Sign(v interface{}) (string, error) {
	return "", nil
}

func (n *none) Verify(t string, v interface{}) error {
	return nil
}

type hs256 struct {
	TTL    int
	Issuer string
	secret string
}

func New(alg, key, iss string, ttl int) (Signer, error) {
	switch strings.ToLower(alg) {
	case "hs256":
		if key == "" {
			return nil, ErrBadSecret
		}
		return &hs256{ttl, iss, key}, nil
	case "":
		return &none{ttl, iss}, nil
	default:
		return nil, fmt.Errorf("unsupported alg %s", alg)
	}
}

func (s hs256) Sign(v interface{}) (string, error) {
	b := claims{
		Payload: v,
		Issuer:  s.Issuer,
		Jid:     strconv.Itoa(int(time.Now().Unix())),
	}
	if n := time.Now(); s.TTL > 0 {
		e := n.Add(time.Second * time.Duration(s.TTL))
		b.Created, b.Expired = &n, &e
	}
	j := jose{
		Typ: JWT,
		Alg: "HS256",
	}
	k := marshalPart(j) + "." + marshalPart(b)

	mac := hmac.New(sha256.New, []byte(s.secret))
	mac.Write([]byte(k))

	return k + "." + std.EncodeToString(mac.Sum(nil)), nil
}

func (s hs256) Verify(t string, v interface{}) error {
	h, p, err := verifyToken(t, s.secret)
	if err != nil {
		return err
	}
	j := new(jose)
	if err := unmarshalPart(h, j); err != nil {
		return ErrMalFormed
	}
	b := &claims{Payload: v}
	if b.Payload == nil {
		b.Payload = make(map[string]interface{})
	}
	if err := unmarshalPart(p, b); err != nil {
		return ErrMalFormed
	}
	return s.validate(b)
}

func (s hs256) validate(b *claims) error {
	if b.Issuer != s.Issuer {
		return ErrInvalid
	}
	if b.Expired == nil || b.Created == nil {
		return nil
	}
	if delta := (*b.Expired).Sub(*b.Created); s.TTL > 0 && int(delta) != s.TTL {
		return ErrInvalid
	}
	if delta := time.Since(*b.Expired); !(*b.Expired).IsZero() && delta > 0 {
		return ErrInvalid
	}
	return nil
}

func verifyToken(t, s string) (string, string, error) {
	ps := strings.Split(t, ".")

	m := hmac.New(sha256.New, []byte(s))
	m.Write([]byte(ps[0] + "." + ps[1]))
	sum := m.Sum(nil)

	if !hmac.Equal([]byte(std.EncodeToString(sum)), []byte(ps[2])) {
		return "", "", ErrBadSignature
	}

	return ps[0], ps[1], nil
}

func marshalPart(v interface{}) string {
	bs, _ := json.Marshal(v)
	return std.EncodeToString(bs)
}

func unmarshalPart(s string, v interface{}) error {
	bs, err := std.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(bs, v)
}
