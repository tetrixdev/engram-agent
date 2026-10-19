package inventory

import (
	"bufio"
	"os"
	"strings"
	"unicode"
)

// Package is one installed package from dpkg's status file.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"` // the source package name (and version when it differs), as dpkg lists it; the name when none
	Arch    string `json:"arch"`
}

// ReadDpkgStatus lists the installed packages ("install ok installed") in
// /var/lib/dpkg/status. A missing file is no packages (not a dpkg system).
func ReadDpkgStatus(path string) ([]Package, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Package
	var cur Package
	var status string
	flush := func() {
		if cur.Name != "" && status == "install ok installed" {
			if cur.Source == "" {
				cur.Source = cur.Name
			}
			out = append(out, cur)
		}
		cur, status = Package{}, ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			flush()
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			continue // a continuation line (Description, Conffiles)
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			cur.Name = v
		case "Status":
			status = v
		case "Version":
			cur.Version = v
		case "Source":
			cur.Source = v
		case "Architecture":
			cur.Arch = v
		}
	}
	flush()
	return out, sc.Err()
}

// CompareVersions compares two Debian versions as dpkg does: <0, 0, >0.
func CompareVersions(a, b string) int {
	ea, ua, ra := splitVersion(a)
	eb, ub, rb := splitVersion(b)
	if c := cmpInt(ea, eb); c != 0 {
		return c
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitVersion(v string) (epoch int, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		for _, c := range v[:i] {
			if c >= '0' && c <= '9' {
				epoch = epoch*10 + int(c-'0')
			}
		}
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func order(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case unicode.IsLetter(rune(c)):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	}
	return int(c) + 256
}

// verrevcmp is dpkg's own comparison of an upstream version or revision.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		diff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ac, bc int
			if i < len(a) {
				ac = order(a[i])
			}
			if j < len(b) {
				bc = order(b[j])
			}
			if ac != bc {
				return cmpInt(ac, bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if diff == 0 {
				diff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if diff != 0 {
			return cmpInt(diff, 0)
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
