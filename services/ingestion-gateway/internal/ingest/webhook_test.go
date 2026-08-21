package ingest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyGitHubSignature(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	secret := "dev-webhook-secret"
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	header := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if !verifyGitHubSignature(body, header, secret) {
		t.Fatal("expected valid signature")
	}
	if verifyGitHubSignature(body, header, "wrong") {
		t.Fatal("expected invalid signature for wrong secret")
	}
	if verifyGitHubSignature(body, "sha256=deadbeef", secret) {
		t.Fatal("expected invalid signature for bad digest")
	}
}
