// Package logs reads recent log lines for `engram-agent logs`: from the
// journal, a docker container or a file under /var/log, bounded and with
// secret-looking strings masked.
package logs

import "regexp"

// The marker format, "[redacted: <what>]", is the one the ai-bridge uses
// (tetrixdev/ai-bridge, src/local/scrub.ts) so a reader can tell a
// redaction from a bug. The bridge redacts known values; here no values are
// known, so these patterns are written for this: the token shapes the major
// services publish, private keys, JWTs, credentials in URLs and headers,
// and key=value pairs whose key names a secret.
//
// It is hygiene, not containment: it catches what a log line carries by
// accident, not what someone wrote to defeat it.

type pattern struct {
	name string
	re   *regexp.Regexp
	// keep is how many leading submatches stay (the "password=" in
	// "password=hunter2"); 0 replaces the whole match.
	keep int
}

var patterns = []pattern{
	{"private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)`), 0},
	{"aws key", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), 0},
	{"github token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`), 0},
	{"gitlab token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), 0},
	{"slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`), 0},
	{"stripe key", regexp.MustCompile(`\b[rsp]k_(live|test)_[A-Za-z0-9]{16,}\b`), 0},
	{"api key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`), 0}, // OpenAI, Anthropic (sk-ant-...)
	{"google api key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), 0},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), 0},
	{"bearer token", regexp.MustCompile(`(?i)(\b(?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{8,}`), 1},
	{"bearer token", regexp.MustCompile(`(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{16,}`), 1},
	{"url password", regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:)[^\s@/]+(@)`), 2},
	{"secret", regexp.MustCompile(`(?i)(\b[a-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?)\b["']?\s*[:=]\s*["']?)[^\s"',;&\[][^\s"',;&]{2,}`), 1},
}

// Mask replaces secret-looking strings in a line and says how many it replaced.
func Mask(line string) (string, int) {
	n := 0
	for _, p := range patterns {
		line = p.re.ReplaceAllStringFunc(line, func(m string) string {
			n++
			marker := "[redacted: " + p.name + "]"
			if p.keep == 0 {
				return marker
			}
			sub := p.re.FindStringSubmatch(m)
			if p.name == "url password" {
				return sub[1] + marker + sub[2]
			}
			return sub[1] + marker
		})
	}
	return line, n
}
