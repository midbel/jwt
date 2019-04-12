package jwt

import (
	"testing"
)

type user struct {
	Id    string `json:"sub"`
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

func TestVerifyToken(t *testing.T) {
	t.Run("secrets", func(t *testing.T) {
		s1 := New(WithSecret("hello", HS256), WithIssuer("hello.be"))
		s2 := New(WithSecret("world", HS256), WithIssuer("hello.be"))
		testTokensEqual(t, s1, s2)
		testVerifyToken(t, s1, s2)
	})
	t.Run("issuers", func(t *testing.T) {
		s1 := New(WithSecret("hello", HS256), WithIssuer("hello.be"))
		s2 := New(WithSecret("hello", HS256), WithIssuer("world.be"))
		testTokensEqual(t, s1, s2)
		testVerifyToken(t, s1, s2)
	})
}

func TestSignAndVerify(t *testing.T) {
	issuer := WithIssuer("jwt.midbel.be")
	t.Run("hs256", func(t *testing.T) {
		s := New(WithSecret("helloworld", HS256), issuer)
		testSignAndVerify(t, s)
	})
	t.Run("hs512", func(t *testing.T) {
		s := New(WithSecret("helloworld", HS512), issuer)
		testSignAndVerify(t, s)
	})
	t.Run("none", func(t *testing.T) {
		s := New(issuer)
		testSignAndVerify(t, s)
	})
}

func testVerifyToken(t *testing.T, s1, s2 Signer) {
	v := user{
		Id:    "1234567890",
		Name:  "John Doe",
		Admin: true,
	}
	token, err := s1.Sign(v)
	if err != nil {
		t.Errorf("unexpected error when signin: %s", err)
		return
	}
	var w user
	if err := s2.Verify(token, &w); err == nil {
		t.Errorf("token should not be validated by another signer")
	}
}

func testSignAndVerify(t *testing.T, s Signer) {
	v := user{
		Id:    "1234567890",
		Name:  "John Doe",
		Admin: true,
	}
	k, err := s.Sign(v)
	if err != nil {
		t.Errorf("unexpected error when signing: %s", err)
		return
	}

	var w user
	if err := s.Verify(k, &w); err != nil {
		t.Errorf("token verification failed: %s", err)
		return
	}
	if v != w {
		t.Errorf("want: %+v", v)
		t.Errorf("got : %+v", w)
	}
}

func testTokensEqual(t *testing.T, s1, s2 Signer) {
	v := user{
		Id:    "1234567890",
		Name:  "John Doe",
		Admin: true,
	}
	t1, err := s1.Sign(v)
	if err != nil {
		t.Errorf("unexpected error signing 1: %s", err)
		return
	}
	t2, err := s2.Sign(v)
	if err != nil {
		t.Errorf("unexpected error signing 2: %s", err)
		return
	}
	if t1 == t2 {
		t.Errorf("token can not be equal")
	}
}
