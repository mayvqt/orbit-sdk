package orbit

import (
	"strings"
	"testing"
)

func TestMalformedJSONAndJWKSFailWithoutPanic(t *testing.T) {
	cases := []string{
		"", "{", "null", "true", "1", `"text"`, "[]", "{}",
		`{"keys":null}`, `{"keys":{}}`, `{"keys":[null]}`, `{"keys":[true]}`,
		`{"keys":[[]]}`, `{"keys":[{}]}`, `{"keys":[],"keys":[]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":"key","x":[],"y":null}]}`,
		`{"keys":[],"extra":"` + string([]byte{0xff}) + `"}`,
		strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40),
	}
	for index, input := range cases {
		// An unexpected panic fails the test directly rather than being converted
		// into an expected parse error by a recovery wrapper.
		if _, err := parseKeys([]byte(input)); err == nil {
			t.Fatalf("malformed JWKS case %d accepted", index)
		}
		var reply grantReply
		if err := decodeJSON([]byte(input), &reply); err == nil {
			t.Fatalf("malformed grant response case %d accepted", index)
		}
	}
	for _, input := range []string{`{"accepted":true,"accepted":false}`, `{"accepted":true,"Accepted":false}`, `{"accepted":null}`, `{"accepted":"true"}`, `{"accepted":true} trailing`} {
		var reply acceptedReply
		if err := decodeJSON([]byte(input), &reply); err == nil {
			t.Fatalf("malformed required boolean accepted: %q", input)
		}
	}
}
