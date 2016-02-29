package main

import "testing"

var pubkey = "ssh-dss AAAAB3NzaC1kc3MAAAEBAINhoWrloDbVkggrbanGpDtBZbPvQAYu2l58skefp92yTOyJEPQcQeYcKJUKdF8psqY51RRZGx0s9aakCBZzMVl3RDkca9KBrqvd4Dr8GI7AwI81CxL4EumGJ2Mey393ctAV+SDUzHVaTHEB0TYOeQiR6d/+bV4lR5cm28xmsdnv1jZChq4eu/3eBKPMMyXeqKwrJ54qaPXlLk20Ts92PXJo+4CG26vn2yVMYhThMF/uRNgmUgEL7gyeGWaQAq0YzWbuUzYcgQzt6tMWKMix1qg++qGFKGtkm/3sGZS6m5IkoBbl+D/TRuiN+6MpYWhAERCx/YF8cnScMeA5slxczg0AAAAVAJxdmop66JPzEqsKFt21fZdprN2LAAABACayECny7fETC+p1vSL2fjOE0f0o47eRONeiz4e+nnZtCcJKpuaLfCA1pMbRKTgDOngsUz2KODWjZTFc81lUV7uGo0ij6ULBdBOLEvS/3l7onh9VCYkrap3YCwg+Ku7gZViy1MSSK8snPMTmF8N3pkz/fKxIJGaMwm15Jzwx5kvnq5GQb+mby/Cfw8WHFXmsdPDQiDS+zzwQJX8/GMT9z+VUvdWKMfHSCb+702ygsPnOvEodCXkY5D4miIuKjm60taRFQbWtq+X0PTRadxn64s9mjfvTBgrvUh0WwtUGD94GVYLN/vdNSAN+3QQi1hiKgNcDnm+0QNJjHAbEJIZ1cy4AAAEAKAQwsSVn8CSSNnWd0Yd4j5917pkyrekCnLiUPXOXbnCtaXa16+7HYX/kDrgsxhNV/YGhbU8w1iBe7DfYPnbT1B5bEBcWCqlPJXyYYBD+C7fNZT0z7h0JEV+tRW5epWDzbdLCB9jheQCK5SU84QRbmzj0+aakkjI+zg7ZZgMhOUSu1axWJtMK7wDAswVNIpkuzCZLGI30Muc2KMBHOzO3WrBv/sICzbhyOc9BBHBhQg11+Hgt+ryCzDyJqNY0aA5IoOtu1UFpt820dgelOcOIw2CFacMaiLL4DyOe+e/20cgYIUUkpYWPdoNMKSKGhUb5rdBy1WP01ElbkXztpoD1Wg== jbarratt@dhcp"

var fingerprint = "7hAZTCeFBwUF1sIlU8JoGEPkJxdS0ln2Tskfl38ATSo"

var loglines = []string{
	"Feb 26 20:16:40 ip-10-0-0-250 sshd[17165]: Accepted publickey for domain.com from 74.51.211.142 port 2234 ssh2: RSA SHA256:NX0TadtGtNnRbIpjyV51bkhs1yR4BJHPXFIp2aFeXWs",
	"Feb 26 22:34:32 ip-10-0-0-250 sshd[1405]: Accepted publickey for ubuntu from 72.10.62.12 port 58756 ssh2: RSA SHA256:crVOTUzam67DWzmqTi0DEUmjxjHfdVXIhjKBadyrW24",
	"Feb 27 16:50:32 ip-10-0-0-250 sshd[12567]: Accepted publickey for ubuntu from 24.21.159.244 port 62601 ssh2: DSA SHA256:7hAZTCeFBwUF1sIlU8JoGEPkJxdS0ln2Tskfl38ATSo",
	"Non-matching-line",
}

func TestKeyFingerprinter(t *testing.T) {
	keyEntry, err := NewAuthKey(pubkey)
	if err != nil {
		t.Fatalf("Parse error extracting key")
	}
	if keyEntry.fingerprint != fingerprint {
		t.Fatalf("Fingerprint (%s) doesn't match expected (%s)", keyEntry.fingerprint, fingerprint)
	}
	if keyEntry.comment != "jbarratt@dhcp" {
		t.Fatalf("Failed to extract comment")
	}
}

func TestParser(t *testing.T) {
	for i, l := range loglines {
		entry, err := NewSSHLogEntry(l)
		switch {
		case i == 0:
			if entry.user != "domain.com" || entry.fingerprint != "NX0TadtGtNnRbIpjyV51bkhs1yR4BJHPXFIp2aFeXWs" {
				t.Fatalf("Error parsing domain.com entry")
			}
		case i == 3:
			if err == nil {
				t.Fatalf("non-matching-line should return an error")
			}
		}
	}
}
