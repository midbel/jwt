package jwt

import (
	"encoding/pem"
	"testing"
	"time"
)

type user struct {
	Id    string `json:"sub"`
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
}

func init() {
	timeNow = func() time.Time {
		return time.Date(2019, 6, 11, 11, 45, 0, 0, time.UTC)
	}
	timeSince = func(_ time.Time) time.Duration {
		return time.Hour
	}
}

func TestVerifyToken(t *testing.T) {
	t.Run("secrets", func(t *testing.T) {
		s1, _ := New(WithSecret([]byte("hello"), HS256), WithIssuer("hello.be"))
		s2, _ := New(WithSecret([]byte("world"), HS256), WithIssuer("hello.be"))
		testTokensEqual(t, s1, s2)
		testVerifyToken(t, s1, s2)
	})
	t.Run("issuers", func(t *testing.T) {
		s1, _ := New(WithSecret([]byte("hello"), HS256), WithIssuer("hello.be"))
		s2, _ := New(WithSecret([]byte("hello"), HS256), WithIssuer("world.be"))
		testTokensEqual(t, s1, s2)
		testVerifyToken(t, s1, s2)
	})
	t.Run("expiration", func(t *testing.T) {
		s, _ := New(WithSecret([]byte("helloworld"), HS256), WithIssuer("hello.be"), WithTime(10*time.Second, 0))
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
		if err := s.Verify(k, &w); err == nil {
			t.Errorf("token should have expired but is not")
			return
		}
	})
}

func TestSignAndVerify(t *testing.T) {
	issuer := WithIssuer("jwt.midbel.be")
	t.Run("hs-all", func(t *testing.T) {
		for _, a := range []string{HS256, HS384, HS512} {
			s, _ := New(WithSecret([]byte("helloworld"), a), issuer)
			testSignAndVerify(t, s, a)
		}
	})
	t.Run("ecdsa-ano", func(t *testing.T) {
		s, _ := New(WithECDSA(), issuer)
		testSignAndVerify(t, s, "anonym")
	})
	t.Run("ecdsa-all", func(t *testing.T) {
		const pemkey = `
-----BEGIN ECDSA PRIVATE KEY-----
MHcCAQEEIG3Yscij+q3nO4nRGAa9SYpWlRoB18fiRDdZjAlw4E8roAoGCCqGSM49
AwEHoUQDQgAEmnQbK6KlKBEGirF+SQFWLr0eDmLrhK1cOq949bTC9KEF7eNuJrzq
nSIevyE15B188DUESW0ByfpxjofXdZ138A==
-----END ECDSA PRIVATE KEY-----
		`
		block, _ := pem.Decode([]byte(pemkey))
		if block == nil {
			t.Errorf("fail to decode pem key")
			return
		}
		for _, a := range []string{ES256, ES384, ES512} {
			s, _ := New(WithSecret(block.Bytes, a), issuer)
			testSignAndVerify(t, s, a)
		}
	})
	t.Run("none", func(t *testing.T) {
		s, _ := New(issuer)
		testSignAndVerify(t, s, "none")
	})
	t.Run("rsa-all", func(t *testing.T) {
		const pemkey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDNAUcV/wifMiJXeNvewMwHO/cSkYEaLAD+OxgZ9WumYmxvkJ4n
TlJQhjwP/tNOvVVB6ObmnAyeq9seE+vB6jMnwTk4jLwaaP6f8apWw1i2WU6iVRNu
SCARfw42rRQyi/pY2utQTcxAWms/+TCNbyZzarD9M91R/kpgrII/H8sVkwIDAQAB
AoGAf6aUBPZRAA/Ponf3MLUMVlTYfA9uPEW6OJPDZiaTaX9P1ghO8lqqlsl/DNa3
7Qen1uqXHHF+yi5oukndO1oBj1nHmw6LM1Tf/q9+BeRgGJKS2aEWfTKYBelj4bZW
wNQTESkpjGzinOHrWXq4IfQYNvKUgNlAQKkw7/8djZStkUECQQDXoBmeM40HjVOo
7fPipfJRkiYTfjmkKIq65CAZ4TBb0IkR8Abz+dhT+mxu7p5CO2DgI6v+nuFTq6H3
Za5Wj+59AkEA82QYBIaiKEJzrvxj3czU4ES28wpmuDWah+El6wWyErrRKeyltBAS
+zKS9mYW2KRXR2GVX/7kb+RlYCliP9oBTwJAfbI6vNpYUBq2tjdggLM0OxDzWVGv
0F5B4QizHeMECcHa5bYCl58B2JKXO2Ompf1vT7n7vYZo3BmlZU7E/nkREQJAMBvG
y445GzAXYa0tqDfGlBXA+8VAjIS76MPOFOhpTF503Y6TKkZLGi/i8KU5OtUxE0Ds
n67oRF2m1B0Z+HkE7QJBAITb9dXsZkQV+H0LgMXlu0Jjr4RWASG4mnYRyIg+5JnF
GtHYmbACMxUVIKcRCrDKFTuRymtISC2GE94S3iFxp8c=
-----END RSA PRIVATE KEY-----
		`
		block, _ := pem.Decode([]byte(pemkey))
		if block == nil {
			t.Errorf("fail to decode pem key")
			return
		}
		for _, a := range []string{RS256, RS384, RS512, PS256, PS384, PS512} {
			s, _ := New(WithSecret(block.Bytes, a))
			testSignAndVerify(t, s, a)
		}
	})
	t.Run("rsa-pkcs-ano", func(t *testing.T) {
		s, _ := New(issuer, WithPKCS(2048))
		testSignAndVerify(t, s, "anonym")
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

func testSignAndVerify(t *testing.T, s Signer, alg string) {
	v := user{
		Id:    "1234567890",
		Name:  "John Doe",
		Admin: true,
	}
	k, err := s.Sign(v)
	if err != nil {
		t.Errorf("unexpected error when signing: %s (%s)", err, alg)
		return
	}

	var w user
	if err := s.Verify(k, &w); err != nil {
		t.Errorf("token verification failed: %s (%s)", err, alg)
		return
	}
	if v != w {
		t.Errorf("want: %+v", v)
		t.Errorf("got : %+v", w)
	}
	// t.Logf("alg [%s]: %s", alg, k)
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
