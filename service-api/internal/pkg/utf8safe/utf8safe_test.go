package utf8safe

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSanitizeJSONB_stripsNULInJSONString(t *testing.T) {
	t.Parallel()

	in := []byte(`{"response_body":"pre\u0000post"}`)
	out := SanitizeJSONB(in)

	if bytes.Contains(out, []byte(`\u0000`)) {
		t.Fatalf("output still contains \\u0000: %s", out)
	}

	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("unmarshal out: %v", err)
	}

	body, ok := m["response_body"].(string)
	if !ok {
		t.Fatalf("response_body type %T", m["response_body"])
	}

	want := "pre" + replacement + "post"
	if body != want {
		t.Fatalf("body %q want %q", body, want)
	}
}

func TestSanitizeJSONB_preservesNonJSONPassThrough(t *testing.T) {
	t.Parallel()

	in := []byte(`not json at all`)
	out := SanitizeJSONB(in)
	if !bytes.Equal(out, in) {
		t.Fatalf("expected unchanged, got %q", out)
	}
}

func TestSanitizeJSONB_nested(t *testing.T) {
	t.Parallel()

	in := []byte(`{"a":{"b":["x\u0000y"]}}`)
	out := SanitizeJSONB(in)

	if bytes.Contains(out, []byte(`\u0000`)) {
		t.Fatalf("output still contains \\u0000: %s", out)
	}
}
