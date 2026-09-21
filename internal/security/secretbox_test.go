package security

import "testing"

func TestSecretBoxEncryptsAndDecryptsWithoutPlaintext(t *testing.T) {
	box, err := NewSecretBox("test-encryption-key")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := box.EncryptMap(map[string]string{"token": "provider-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == "" || ciphertext == "provider-secret" {
		t.Fatalf("unsafe ciphertext: %q", ciphertext)
	}
	values, err := box.DecryptMap(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if values["token"] != "provider-secret" {
		t.Fatalf("decrypted values = %#v", values)
	}
}
