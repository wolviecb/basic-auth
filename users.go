// (C) Modifications copyright 2019, Tom Andrade <wolvie@gmail.com>

// Package auth is a implementation of HTTP Basic in Go language.
package auth

import (
	"encoding/csv"
	"os"
	"sync"
)

// SecretProvider is used by authenticators. Takes user name and realm
// as an argument, returns secret required for authentication (HA1 for
// digest authentication, properly encrypted password for basic).
//
// Returning an empty string means failing the authentication.
type SecretProvider func(user, realm string) string

// File handles automatic file reloading on changes.
type File struct {
	Path string
	Info os.FileInfo
	/* must be set in inherited types during initialization */
	Reload func()
	mu     sync.Mutex
}

// ReloadIfNeeded checks file Stat and calls Reload() if any changes
// were detected. File mutex is Locked for the duration of Reload()
// call.
//
// This function will panic() if Stat fails.
func (f *File) ReloadIfNeeded() {
	info, err := os.Stat(f.Path)
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Info == nil || f.Info.ModTime() != info.ModTime() {
		f.Info = info
		f.Reload()
	}
}

// HtpasswdFile is a File holding basic authentication data.
type HtpasswdFile struct {
	// File is used for automatic reloading of the authentication data.
	File
	// Users is a map of users to their secrets (salted encrypted
	// passwords).
	Users map[string]string
	mu    sync.RWMutex
}

func reloadHTPasswd(h *HtpasswdFile) {
	r, err := os.Open(h.Path)
	if err != nil {
		panic(err)
	}
	reader := csv.NewReader(r)
	reader.Comma = ':'
	reader.Comment = '#'
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		panic(err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.Users = make(map[string]string)
	for _, record := range records {
		h.Users[record[0]] = record[1]
	}
}

// HtpasswdFileProvider is a SecretProvider implementation based on
// htpasswd-formated files. It will automatically reload htpasswd file
// on changes. It panics on syntax errors in htpasswd files. Realm
// argument of the SecretProvider is ignored.
func HtpasswdFileProvider(filename string) SecretProvider {
	h := &HtpasswdFile{File: File{Path: filename}}
	h.Reload = func() { reloadHTPasswd(h) }
	return func(user, realm string) string {
		h.ReloadIfNeeded()
		h.mu.RLock()
		password, exists := h.Users[user]
		h.mu.RUnlock()
		if !exists {
			return ""
		}
		return password
	}
}
