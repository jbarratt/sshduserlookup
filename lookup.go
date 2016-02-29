package main

import (
	"bufio"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/user"
	"path/filepath"
	"sync"
)

type keyCache struct {
	lock  sync.RWMutex
	cache map[sshLogEntry]authKeyEntry
}

var cache keyCache
var logger *syslog.Writer

func init() {
	cache = keyCache{cache: make(map[sshLogEntry]authKeyEntry)}
	var e error
	logger, e = syslog.New(syslog.LOG_INFO|syslog.LOG_AUTH, "sshd_lookup")
	if e != nil {
		logger = nil
	}
}

// lookupOwner consults a shared cache of users and, if not found
// searches the system for the proper authorized keys file, caches the result
// In either path, it then syslogs the result
func lookupOwner(l sshLogEntry) {
	cache.lock.RLock()
	authKey, ok := cache.cache[l]
	cache.lock.RUnlock()

	if ok {
		syslogKey(l, authKey)
		return
	}

	user, err := user.Lookup(l.user)
	if err != nil {
		log.Println("Warning: unable to look up user", l.user, err)
		return
	}

	authKeyPath := filepath.Join(user.HomeDir, ".ssh", "authorized_keys")
	file, err := os.Open(authKeyPath)
	if err != nil {
		log.Println("Unable to read authorized_keys file for ", l.user)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		key, err := NewAuthKey(scanner.Text())
		if err != nil {
			log.Printf("%s's authorized key file contained malformed line %s: %s", l.user, scanner.Text(), err)
			continue
		}
		// found a match, awesome
		if key.fingerprint == l.fingerprint {
			cache.lock.Lock()
			cache.cache[l] = key
			cache.lock.Unlock()
			syslogKey(l, key)
			return
		}
		// TODO, optionally cache all other entries we've parsed in the file
	}
}

func syslogKey(l sshLogEntry, k authKeyEntry) {
	if logger != nil {
		logger.Write([]byte(fmt.Sprintf("User login to '%s' was with SSH Key having comment '%s'", l.user, k.comment)))
	}
}
