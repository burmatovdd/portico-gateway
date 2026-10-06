package vault

import "testing"

func TestCiphertextCannotMoveBetweenSessions(t *testing.T) {
	v, err := New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	data, err := v.Seal([]byte("refresh-secret"), "session-a")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := v.Open(data, "session-a")
	if err != nil || string(plain) != "refresh-secret" {
		t.Fatal("round trip failed")
	}
	if _, err = v.Open(data, "session-b"); err == nil {
		t.Fatal("accepted ciphertext from another session")
	}
	data[len(data)-1] ^= 1
	if _, err = v.Open(data, "session-a"); err == nil {
		t.Fatal("accepted modified ciphertext")
	}
}
func TestRejectsWrongKeyLength(t *testing.T) {
	if _, err := New([]byte("password")); err == nil {
		t.Fatal("accepted weak key")
	}
}
