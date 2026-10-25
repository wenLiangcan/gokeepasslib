package gokeepasslib

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestArgon2idDerivation(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion41())
	db.Credentials = NewPasswordCredentials("synthetic test password")
	p := db.Header.FileHeaders.KdfParameters
	p.UUID = append([]byte(nil), KdfArgon2id...)
	p.Memory, p.Iterations, p.Parallelism = 8*1024*1024, 2, 2
	composite, err := db.Credentials.buildCompositeKey()
	if err != nil {
		t.Fatal(err)
	}
	expected := argon2.IDKey(composite, p.Salt[:], 2, 8192, 2, 32)
	actual, err := db.Credentials.buildTransformedKey(db)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("Argon2id UUID did not select IDKey with KDBX memory units")
	}
	p.UUID = KdfArgon2
	other, err := db.Credentials.buildTransformedKey(db)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(actual, other) {
		t.Fatal("Argon2d and Argon2id produced the same key")
	}
}

func TestArgon2idEncodeDecode(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion41())
	db.Credentials = NewPasswordCredentials("synthetic test password")
	p := db.Header.FileHeaders.KdfParameters
	p.UUID = append([]byte(nil), KdfArgon2id...)
	p.Memory, p.Iterations, p.Parallelism = 8*1024*1024, 2, 2
	var encrypted bytes.Buffer
	if err := NewEncoder(&encrypted).Encode(db); err != nil {
		t.Fatal(err)
	}
	opened := NewDatabase()
	opened.Credentials = db.Credentials
	if err := NewDecoder(bytes.NewReader(encrypted.Bytes())).Decode(opened); err != nil {
		t.Fatal(err)
	}
	got := opened.Header.FileHeaders.KdfParameters
	if !bytes.Equal(got.UUID, KdfArgon2id) || got.Memory != p.Memory || got.Iterations != p.Iterations || got.Parallelism != p.Parallelism || got.Version != p.Version {
		t.Fatal("Argon2id parameters changed during serialization")
	}
	opened.Credentials = NewPasswordCredentials("wrong password")
	if err := NewDecoder(bytes.NewReader(encrypted.Bytes())).Decode(opened); err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestUnknownKDFRejected(t *testing.T) {
	db := NewDatabase(WithDatabaseKDBXVersion41())
	db.Credentials = NewPasswordCredentials("synthetic test password")
	db.Header.FileHeaders.KdfParameters.UUID = make([]byte, 16)
	if _, err := db.Credentials.buildTransformedKey(db); err == nil {
		t.Fatal("unknown KDF treated as AES-KDF")
	}
}
