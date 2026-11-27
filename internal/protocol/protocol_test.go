package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestAuthRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := AuthRequest{Version: Version, Token: "secret-token"}
	if err := WriteAuth(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadAuth(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("got %+v, want %+v", out, in)
	}
}

func TestAuthNoToken(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteAuth(&buf, AuthRequest{Version: 1}); err != nil {
		t.Fatal(err)
	}
	out, err := ReadAuth(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if out.Token != "" || out.Version != 1 {
		t.Fatalf("got %+v", out)
	}
}

func TestWriteAuthRejectsWhitespaceToken(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteAuth(&buf, AuthRequest{Version: 1, Token: "a b"}); err == nil {
		t.Fatal("expected error for token containing whitespace")
	}
}

func TestReadAuthDoesNotConsumeFollowingBytes(t *testing.T) {
	// Simulate a yamux preamble right after the auth line: ReadAuth
	// must read one byte at a time and leave it untouched.
	var buf bytes.Buffer
	_ = WriteAuth(&buf, AuthRequest{Version: 1})
	buf.WriteString("YAMUX-DATA")

	if _, err := ReadAuth(&buf); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "YAMUX-DATA" {
		t.Fatalf("trailing bytes lost: %q", got)
	}
}

func TestReadAuthMalformed(t *testing.T) {
	for _, s := range []string{"", "HELLO/1\n", "GOTUNNEL/x\n", "GOTUNNEL\n"} {
		if _, err := ReadAuth(strings.NewReader(s)); err == nil {
			t.Fatalf("expected error for %q", s)
		}
	}
}

func TestAuthResultRoundTrip(t *testing.T) {
	var ok bytes.Buffer
	if err := WriteAuthResult(&ok, true, ""); err != nil {
		t.Fatal(err)
	}
	if got, _, err := ReadAuthResult(&ok); err != nil || !got {
		t.Fatalf("ok result: got=%v err=%v", got, err)
	}

	var bad bytes.Buffer
	if err := WriteAuthResult(&bad, false, "nope\nsneaky"); err != nil {
		t.Fatal(err)
	}
	got, msg, err := ReadAuthResult(&bad)
	if err != nil {
		t.Fatal(err)
	}
	if got || msg != "nope sneaky" {
		t.Fatalf("err result: got=%v msg=%q", got, msg)
	}
}

func TestReadAuthResultMalformed(t *testing.T) {
	if _, _, err := ReadAuthResult(strings.NewReader("MAYBE\n")); err == nil {
		t.Fatal("expected error")
	}
}
