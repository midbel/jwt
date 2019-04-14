//Package jwt provides a basic implementation of JSON Web Token as described in
//RFC 7519.
package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
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

	//ErrMalformed is returned when the token does not have the expected format
	//as described in the RFC.
	ErrMalformed = errors.New("malformed token")

	//ErrInvalid is returned when the token hasn't the good issuer or when it has
	//expired or when the issue at is after the expiration time. ErrInvalid is
	//also returned when the payload can not be unmarshaled from the token.
	ErrInvalid = errors.New("invalid token")
)

const (
	HS256 = "HS256"
	HS384 = "HS384"
	HS512 = "HS512"
	RS256 = "RS256"
	RS384 = "RS384"
	RS512 = "RS512"
	ES256 = "ES256"
	ES384 = "ES384"
	ES512 = "ES512"
	None  = "none"
)

type Signer struct {
	alg    string
	issuer string
	ttl    time.Duration

	sign signer
}

func New(options ...Option) (Signer, error) {
	var s Signer

	s.alg, s.sign = None, nonehash{}
	for _, o := range options {
		if err := o(&s); err != nil {
			return s, err
		}
	}
	return s, nil
}

type Option func(*Signer) error

func WithSecret(secret []byte, alg string) Option {
	return func(s *Signer) error {
		var sign signer
		switch alg {
		case HS256, HS512, HS384, "":
			h, err := hmacSigner(alg, secret)
			if err != nil {
				return err
			}
			sign = h
		case RS256, RS384, RS512:
			if s, err := pkcsSigner(alg, secret); err != nil {
				return err
			} else {
				sign = s
			}
		case ES256, ES512:
			if s, err := ecdsaSigner(alg, secret); err != nil {
				return err
			} else {
				sign = s
			}
		default:
			return fmt.Errorf("unkown algorithm: %s", alg)
		}
		s.sign, s.alg = sign, alg
		return nil
	}
}

func WithPKCS(size int) Option {
	return func(s *Signer) error {
		sign, err := pkcsSigner(RS256, nil)
		if err == nil {
			s.sign, s.alg = sign, RS256
		}
		return err
	}
}

func WithECDSA() Option {
	return func(s *Signer) error {
		es, err := ecdsaSigner(ES256, nil)
		if err == nil {
			s.sign = es
		}
		return err
	}
}

func WithIssuer(issuer string) Option {
	return func(s *Signer) error {
		s.issuer = issuer
		return nil
	}
}

func WithTTL(ttl time.Duration) Option {
	return func(s *Signer) error {
		if ttl >= time.Second {
			s.ttl = ttl
		}
		return nil
	}
}

func (s Signer) Sign(v interface{}) (string, error) {
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
	j := jose(s.alg)
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
		return ErrMalformed
	}
	b := claims{Payload: v}
	if b.Payload == nil {
		b.Payload = make(map[string]interface{})
	}
	if err := unmarshalPart(p, &b); err != nil {
		return ErrMalformed
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

type jose string

func (j *jose) MarshalJSON() ([]byte, error) {
	v := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{
		Alg: string(*j),
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
		return ErrMalformed
	}
	if v.Alg == "" {
		return ErrMalformed
	}
	*j = jose(v.Alg)
	// j.Alg, j.Typ = v.Alg, v.Typ
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

func hmacSigner(alg string, secret []byte) (signer, error) {
	var h hs
	switch alg {
	case HS256, "":
		h.mac = hmac.New(sha256.New, secret)
	case HS384:
		h.mac = hmac.New(sha512.New384, secret)
	case HS512:
		h.mac = hmac.New(sha512.New, secret)
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", alg)
	}
	return &h, nil
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

type ecdsha struct {
	key *ecdsa.PrivateKey
	sum shaFunc
}

func ecdsaSigner(alg string, secret []byte) (signer, error) {
	var (
		pk  *ecdsa.PrivateKey
		err error
	)
	if len(secret) == 0 {
		var curve elliptic.Curve
		switch alg {
		case ES256:
			curve = elliptic.P256()
		case ES384:
			curve = elliptic.P384()
		case ES512:
			curve = elliptic.P521()
		}
		pk, err = ecdsa.GenerateKey(curve, rand.Reader)
	} else {
		pk, err = x509.ParseECPrivateKey(secret)
	}
	if err != nil {
		return nil, err
	}
	sum, err := whichSHA(alg)
	return &ecdsha{pk, sum}, err
}

func (e *ecdsha) Sign(token string) string {
	hashed := e.sum([]byte(token))
	r, s, err := ecdsa.Sign(rand.Reader, e.key, hashed)
	if err == nil {
		c := struct{ R, S *big.Int }{r, s}
		if sign, err := asn1.Marshal(c); err == nil {
			token += "." + std.EncodeToString(sign)
		}
	}
	return token
}

func (e *ecdsha) Verify(token string) (string, string, error) {
	ps, err := splitToken(token)
	if err != nil {
		return "", "", err
	}
	sign, err := std.DecodeString(ps[2])
	if err != nil {
		return "", "", ErrMalformed
	}
	c := struct{ R, S *big.Int }{}
	if _, err := asn1.Unmarshal(sign, &c); err != nil {
		return "", "", ErrMalformed
	}
	hashed := e.sum([]byte(ps[0] + "." + ps[1]))
	if !ecdsa.Verify(&e.key.PublicKey, hashed[:], c.R, c.S) {
		err = ErrInvalid
	}
	return ps[0], ps[1], err
}

type rsapkcs struct {
	key *rsa.PrivateKey
	sum shaFunc
}

func pkcsSigner(alg string, secret []byte) (signer, error) {
	var (
		pk  *rsa.PrivateKey
		err error
	)
	if len(secret) == 0 {
		pk, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		pk, err = x509.ParsePKCS1PrivateKey(secret)
	}
	if err != nil {
		return nil, err
	}
	sum, err := whichSHA(alg)
	return &rsapkcs{pk, sum}, err
}

func (r *rsapkcs) Sign(token string) string {
	hashed := r.sum([]byte(token))

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
		return "", "", ErrMalformed
	}
	hashed := r.sum([]byte(ps[0] + "." + ps[1]))
	err = rsa.VerifyPKCS1v15(&r.key.PublicKey, crypto.SHA256, hashed[:], sign)
	return ps[0], ps[1], err
}

type nonehash struct{}

func (nonehash) Sign(token string) string {
	return token + "."
}

func (nonehash) Verify(token string) (string, string, error) {
	ps, err := splitToken(token)
	if err != nil {
		return "", "", err
	}
	if ps[2] != "" {
		return "", "", ErrMalformed
	}
	return ps[0], ps[1], nil
}

func splitToken(token string) ([]string, error) {
	ps := strings.Split(token, ".")
	if len(ps) != 3 {
		return nil, ErrMalformed
	}
	return ps, nil
}

type shaFunc func([]byte) []byte

func whichSHA(alg string) (shaFunc, error) {
	var f shaFunc
	switch alg {
	case HS256, RS256, ES256:
		f = shaSum256
	case HS384, RS384, ES384:
		f = shaSum384
	case HS512, RS512, ES512:
		f = shaSum512
	default:
		return nil, fmt.Errorf("no shaFunc match given alg %s", alg)
	}
	return f, nil
}

func shaSum256(bs []byte) []byte {
	xs := sha256.Sum256(bs)
	return xs[:]
}

func shaSum384(bs []byte) []byte {
	xs := sha512.Sum384(bs)
	return xs[:]
}

func shaSum512(bs []byte) []byte {
	xs := sha512.Sum512(bs)
	return xs[:]
}
