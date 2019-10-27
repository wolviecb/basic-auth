// (C) Modifications copyright 2019, Tom Andrade <wolvie@gmail.com>

// Package auth is a implementation of HTTP Basic in Go language.
package auth

import (
	"os"
	"testing"
	"time"
)

func TestHtpasswdFile(t *testing.T) {
	t.Parallel()
	secrets := HtpasswdFileProvider("test.htpasswd")
	passwd := secrets("test", "blah")
	if passwd != "{SHA}qvTGHdzF6KLavt4PO0gs2a6pQ00=" {
		t.Fatal("Incorrect passwd for test user:", passwd)
	}
	passwd = secrets("nosuchuser", "blah")
	if passwd != "" {
		t.Fatal("Got passwd for non-existent user:", passwd)
	}
}

// TestConcurrent verifies potential race condition in users reading logic
func TestConcurrent(t *testing.T) {
	t.Parallel()
	secrets := HtpasswdFileProvider("test.htpasswd")
	os.Chtimes("test.htpasswd", time.Now(), time.Now())
	go func() {
		secrets("test", "blah")
	}()
	secrets("test", "blah")
}
