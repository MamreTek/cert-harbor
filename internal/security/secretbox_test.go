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

func TestSecretBoxReencryptsWithPreviousKey(t *testing.T) {
	previous, err := NewSecretBox("old-key")
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewSecretBox("new-key")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := previous.Encrypt([]byte("rotation-secret"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, changed, err := current.Reencrypt(ciphertext, previous)
	if err != nil || !changed {
		t.Fatalf("reencrypt = %q changed=%v err=%v", rotated, changed, err)
	}
	if value, err := current.Decrypt(rotated); err != nil || string(value) != "rotation-secret" {
		t.Fatalf("rotated plaintext = %q err=%v", value, err)
	}
	if _, err := current.Decrypt(ciphertext); err == nil {
		t.Fatal("current key unexpectedly decrypted old ciphertext")
	}
}
