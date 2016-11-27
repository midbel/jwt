package jwt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

const JWT = "jwt"

var (
	ErrBadSignature = errors.New("bad signature")
	ErrBadSecret    = errors.New("bad secret key")
	ErrMalFormed    = errors.New("malformed token")
	ErrInvalid      = errors.New("invalid token")
)

type Signer interface {
	Sign(interface{}) (string, error)
	Verify(string, interface{}) error
}

type body struct {
	Payload interface{} `json:"payload"`
	Issuer  string      `json:"iss,omitempty"`
	Id      string      `json:"jti,omitempty"`
	Created time.Time   `json:"iat"`
	Expire  time.Time   `json:"exp,omitempty"`
}

type hmacSigner struct {
	TTL    int
	Issuer string
	secret string
	alg    string
	sign   func() hash.Hash
}

func NewSigner(key, alg, issuer string, ttl int) (Signer, error) {
	if key == "" {
		return nil, fmt.Errorf("missing key")
	}
	var f func() hash.Hash
	switch strings.ToLower(alg) {
	case "hs256", "":
		f = sha256.New
	case "md5":
		f = md5.New
	default:
		return nil, fmt.Errorf("unsupported alg %s", alg)
	}
	return &hmacSigner{ttl, issuer, key, strings.ToUpper(alg), f}, nil
}

func (s hmacSigner) Sign(p interface{}) (string, error) {
	t := struct {
		Header  string
		Payload string
	}{}
	enc := base64.StdEncoding.WithPadding(base64.NoPadding)

	header := map[string]string{
		"typ": JWT,
		"alg": s.alg,
	}
	var (
		buf []byte
		err error
	)
	buf, err = json.Marshal(header)
	if err != nil {
		return "", err
	}
	t.Header = enc.EncodeToString(buf)

	payload := body{
		Payload: p,
		Issuer:  s.Issuer,
		Id:      strconv.Itoa(int(time.Now().Unix())),
		Created: time.Now(),
	}
	if s.TTL > 0 {
		payload.Expire = time.Now().Add(time.Second * time.Duration(s.TTL))
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	t.Payload = enc.EncodeToString(buf)

	part := t.Header + "." + t.Payload
	mac := hmac.New(s.sign, []byte(s.secret))
	mac.Write([]byte(part))

	return part + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

func (s hmacSigner) Verify(t string, p interface{}) error {
	var (
		ix  int
		buf []byte
		err error
	)
	ix = strings.Index(t, ".")
	if ix < 0 {
		return ErrMalFormed
	}
	h, t := t[:ix], t[ix+1:]

	enc := base64.StdEncoding.WithPadding(base64.NoPadding)

	buf, err = enc.DecodeString(h)
	if err != nil {
		return ErrMalFormed
	}
	header := make(map[string]string)
	if err := json.Unmarshal(buf, &header); err != nil {
		return ErrMalFormed
	}
	if header["typ"] != JWT || header["alg"] != s.alg {
		return ErrInvalid
	}
	ix = strings.Index(t, ".")
	if ix < 0 {
		return ErrMalFormed
	}
	payload, signature := t[:ix], t[ix+1:]

	mac := hmac.New(s.sign, []byte(s.secret))
	mac.Write([]byte(h + "." + payload))
	sum := mac.Sum(nil)

	if !hmac.Equal([]byte(enc.EncodeToString(sum)), []byte(signature)) {
		return ErrBadSignature
	}

	buf, err = enc.DecodeString(payload)
	if err != nil {
		return ErrMalFormed
	}
	b := &body{Payload: p}
	if err := json.Unmarshal(buf, b); err != nil {
		return ErrMalFormed
	}
	if delta := b.Expire.Sub(b.Created); int(delta.Seconds()) != s.TTL {
		return ErrInvalid
	}
	if b.Issuer != s.Issuer {
		return ErrInvalid
	}
	if delta := time.Since(b.Expire); delta > 0 {
		return ErrInvalid
	}
	return nil
}
