package jwt

import (
	"testing"
)

type Sample struct {
	Id    string `json:"sub"`
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

func TestSignAndVerify(t *testing.T) {
	v := Sample{
		Id:    "1234567890",
		Name:  "John Doe",
		Admin: true,
	}
	s, _ := New("hs256", "secret", "", -1)
	k, _ := s.Sign(v)
	w := new(Sample)
	if err := s.Verify(k, w); err != nil {
		t.Errorf("token verification failed: %s", err)
	}
}
