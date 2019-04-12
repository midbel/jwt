package jwt

import (
	"testing"
)

type user struct {
	Id    string `json:"sub"`
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

func TestSignAndVerify(t *testing.T) {
	t.Run("hs256", func(t *testing.T) {
		s := New(WithSecret("helloworld", "hs256"))
		testSignAndVerify(t, s)
	})
	t.Run("none", func(t *testing.T) {
		s := New()
		testSignAndVerify(t, s)
	})
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
	t.Logf("token: %s", k)

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
