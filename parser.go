package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

type sshLogEntry struct {
	user        string
	fingerprint string
}

type authKeyEntry struct {
	key         string
	fingerprint string
	comment     string
}

// handleLine checks to see if a line matches an ssh key fingerprint
// if so, it dispatches a process to look up the user and syslog it
func handleLine(l string) {
	userFp, err := NewSSHLogEntry(l)
	if err != nil {
		return
	}
	go lookupOwner(userFp)
}

// NewSSHLogEntry returns a log entry struct given a log line as input
// "Feb 26 20:16:40 ip-10-0-0-250 sshd[17165]: Accepted publickey for domain.com from 74.51.211.142 port 2234 ssh2: RSA SHA256:NX0TadtGtNnRbIpjyV51bkhs1yR4BJHPXFIp2aFeXWs",
func NewSSHLogEntry(l string) (data sshLogEntry, err error) {
	e := sshLogEntry{}
	p := strings.Split(l, " ")
	if len(p) < 16 {
		return e, errors.New("Unparseable log line")
	}
	e.user = p[8]
	e.fingerprint = p[15]
	if !strings.HasPrefix(e.fingerprint, "SHA256:") {
		return e, errors.New("No SHA256 fingerprint found")
	}
	e.fingerprint = e.fingerprint[7:]
	return e, nil
}

// NewAuthKey returns a constructed authKeyEntry given an authorized keyfile line
func NewAuthKey(s string) (data authKeyEntry, err error) {
	parts := strings.Split(s, " ")
	entry := authKeyEntry{}
	switch {
	case len(parts) < 2:
		return entry, errors.New("Unrecognized key format")
	case len(parts) >= 2:
		entry.key = parts[1]
		fallthrough
	case len(parts) >= 3:
		entry.comment = strings.Join(parts[2:], " ")
	}
	fingerprint, err := fingerprintKey(entry.key)
	if err != nil {
		return entry, errors.New("Unable to generate key fingerprint, invalid key")
	}
	entry.fingerprint = fingerprint
	return entry, nil
}

// fingerprintKey returns the fingerprint of an authorized_keys style entry
// base64 decoded, sha256sum'd, then base64 encoded
func fingerprintKey(s string) (fingerprint string, err error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", errors.New("Can't base64 decode original key")
	}
	sha256 := sha256.New()
	sha256.Write(data)
	b64 := base64.StdEncoding.EncodeToString(sha256.Sum(nil))
	return strings.TrimRight(b64, "="), nil
}
