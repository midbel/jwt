//Package jwt provides a basic implementation of JSON Web Token as described in
//RFC 7519.
//
//This package is not yet fully compliant with the RFC since it does
//yet provide the RS256 algorithm.
package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"strings"
	"time"
)

const JWT = "jwt"

var std = base64.StdEncoding.WithPadding(base64.NoPadding)

var (
	timeNow   = time.Now
	timeSince = time.Since
)

//Common errors type
var (
	//ErrSignature is returned when the signature of token does not match the
	//expected signature generated with the secret key
	ErrSignature = errors.New("bad signature")

	//ErrMalFormed is returned when the token does not have the expected format
	//as described in the RFC.
	ErrMalFormed = errors.New("malformed token")

	//ErrInvalid is returned when the token hasn't the good issuer or when it has
	//expired or when the issue at is after the expiration time. ErrInvalid is
	//also returned when the payload can not be unmarshaled from the token.
	ErrInvalid = errors.New("invalid token")
)

const (
	HS256 = "HS256"
	HS512 = "HS512"
	None  = "none"
)

type Signer struct {
	alg    string
	issuer string
	ttl    time.Duration

	sign signer
}

func New(options ...Option) Signer {
	var s Signer

	s.alg, s.sign = None, nonehash{}
	for _, o := range options {
		o(&s)
	}
	return s
}

type Option func(*Signer)

func WithSecret(secret, alg string) Option {
	return func(s *Signer) {

		var h hs
		switch alg {
		case HS256:
			h.mac = hmac.New(sha256.New, []byte(secret))
		case HS512:
			h.mac = hmac.New(sha512.New, []byte(secret))
		default:
			return
		}
		s.sign = &h
	}
}

func WithPKCS(size int) Option {
	return func(s *Signer) {
		pk, err := rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return
		}
		s.sign = &rsapkcs{pk}
	}
}

func WithIssuer(issuer string) Option {
	return func(s *Signer) {
		s.issuer = issuer
	}
}

func WithTTL(ttl time.Duration) Option {
	return func(s *Signer) {
		if ttl < time.Second {
			return
		}
		s.ttl = ttl
	}
}

func (s Signer) Sign(v interface{}) (string, error) {
	// defer s.mac.Reset()

	now := timeNow()
	b := claims{
		Payload: v,
		Issuer:  s.issuer,
		Id:      now.Unix(),
		Created: &now,
	}
	if e := now.Add(s.ttl); s.ttl > 0 {
		b.Expired = &e
	}
	j := jose{
		Alg: s.alg,
	}
	k := marshalPart(&j) + "." + marshalPart(b)
	return s.sign.Sign(k), nil
}

func (s Signer) Verify(token string, v interface{}) error {
	h, p, err := s.sign.Verify(token)
	if err != nil {
		return err
	}
	var j jose
	if err := unmarshalPart(h, &j); err != nil {
		return ErrMalFormed
	}
	b := claims{Payload: v}
	if b.Payload == nil {
		b.Payload = make(map[string]interface{})
	}
	if err := unmarshalPart(p, &b); err != nil {
		return ErrMalFormed
	}
	return s.validate(b)
}

func (s Signer) validate(b claims) error {
	if s.issuer != "" && b.Issuer != s.issuer {
		return ErrInvalid
	}
	if b.Expired == nil || b.Created == nil {
		return nil
	}
	if delta := timeSince(*b.Created); s.ttl > 0 && delta >= s.ttl {
		return ErrInvalid
	}
	if delta := timeSince(*b.Expired); !(*b.Expired).IsZero() && delta > 0 {
		return ErrInvalid
	}
	return nil
}

type jose struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func (j *jose) MarshalJSON() ([]byte, error) {
	v := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{
		Alg: j.Alg,
		Typ: JWT,
	}
	bs, err := json.Marshal(v)
	return bs, err
}

func (j *jose) UnmarshalJSON(bs []byte) error {
	v := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{}
	if err := json.Unmarshal(bs, &v); err != nil {
		return err
	}
	if v.Typ != JWT {
		return ErrMalFormed
	}
	j.Alg, j.Typ = v.Alg, v.Typ
	return nil
}

type claims struct {
	Payload interface{} `json:"payload"`
	Issuer  string      `json:"iss,omitempty"`
	Id      int64       `json:"jti,omitempty"`
	Created *time.Time  `json:"iat,omitempty"`
	Expired *time.Time  `json:"exp,omitempty"`
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

type signer interface {
	Sign(string) string
	Verify(string) (string, string, error)
}

type hs struct {
	mac hash.Hash
}

func (h *hs) Sign(token string) string {
	defer h.mac.Reset()

	h.mac.Write([]byte(token))
	return token + "." + std.EncodeToString(h.mac.Sum(nil))
}

func (h *hs) Verify(token string) (string, string, error) {
	ps, err := splitToken(token)
	if err != nil {
		return "", "", err
	}
	defer h.mac.Reset()
	h.mac.Write([]byte(ps[0] + "." + ps[1]))
	sum := h.mac.Sum(nil)

	if prev, e := std.DecodeString(ps[2]); e != nil || !hmac.Equal(sum, prev) {
		err = ErrSignature
	}
	return ps[0], ps[1], err
}

type rsapkcs struct {
	key *rsa.PrivateKey
}

func (r *rsapkcs) Sign(token string) string {
	hashed := sha256.Sum256([]byte(token))

	sign, err := rsa.SignPKCS1v15(rand.Reader, r.key, crypto.SHA256, hashed[:])
	if err == nil {
		token += "." + std.EncodeToString(sign)
	}
	return token
}

func (r *rsapkcs) Verify(token string) (string, string, error) {
	ps, err := splitToken(token)
	if err != nil {
		return "", "", err
	}
	sign, err := std.DecodeString(ps[2])
	if err != nil {
		return "", "", ErrMalFormed
	}
	hashed := sha256.Sum256([]byte(ps[0] + "." + ps[1]))
	err = rsa.VerifyPKCS1v15(&r.key.PublicKey, crypto.SHA256, hashed[:], sign)
	return ps[0], ps[1], err
}

type nonehash struct{}

func (_ nonehash) Sign(token string) string {
	return token + "."
}

func (_ nonehash) Verify(token string) (string, string, error) {
	ps, err := splitToken(token)
	if err != nil {
		return "", "", err
	}
	if ps[2] != "" {
		return "", "", ErrMalFormed
	}
	return ps[0], ps[1], nil
}

func splitToken(token string) ([]string, error) {
	ps := strings.Split(token, ".")
	if len(ps) != 3 {
		return nil, ErrMalFormed
	}
	return ps, nil
}
