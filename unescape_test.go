package main_test

import (
	. "github.com/DECK36/go-log2amqp"
	"testing"
)

// copied from http://golang.org/src/pkg/strconv/quote_test.go
type escTest struct {
	in  string
	out string
}

var esctests = []escTest{
	{``, ``},
	{`a`, `a`},
	{`ab`, `ab`},
	{`abc`, `abc`},
	{`hello`, `hello`},
	{`he\"llo`, `he\"llo`},
	{`he\\llo`, `he\\llo`},
	{`he\\"llo`, `he\\\"llo`},   // invalid input, apache workaround
	{`he\\\"llo`, `he\\\"llo`},
	{`he\\\\"llo`, `he\\\\\"llo`}, // invalid input, apache workaround
	{`\hello`, `\\hello`},
	{`h\ello`, `h\\ello`},
	{`he\llo`, `he\\llo`},
	{`hel\lo`, `hel\lo`}, // known bug, do not check last two chars
	{`hell\o`, `hell\o`}, // known bug, do not check last two chars
	{`hello\`, `hello\`}, // known bug, do not check last two chars
	{`\x00hello`, `\\x00hello`},
	{`\x11hello`, `\\x11hello`},
	{`\x22hello`, `\\x22hello`},
	{`\x23hello`, `#hello`},
	{`\x5Chello`, `\\x5Chello`},
	{`\x5Dhello`, `]hello`},
	{`\x\x5Dhello`, `\\x]hello`},
	{`\x\x\x5Dhello`, `\\x\\x]hello`},
	{`\x5D hello`, `] hello`},
	{`\x5D\hello`, `]\\hello`},
	{`\x5D\\hello`, `]\\hello`},
	{`\x5D\xhello`, `]\\xhello`},
	{`{"field":"\xC3\xBCmlaut"}`, `{"field":"ümlaut"}`},
	{`{"fi\xC3\xABld":"value"}`, `{"fiëld":"value"}`},
	{`{"fi\xc3\xabld":"value"}`, `{"fiëld":"value"}`},
	{`{"fi\xc3\xabld":"val\x22ue"}`, `{"fiëld":"val\\x22ue"}`}, // special: \x22 = "
	{`{"fi\xc3\xabld":"value\x22"}`, `{"fiëld":"value\\x22"}`},
	{`{"fi\xc3\xabld\x22":"value"}`, `{"fiëld\\x22":"value"}`},
	// good string
	{` "load/\\\"https:\\/\\/s3-eu-west-1.amazonaws.com\\/1.svg\\\"  "`,
	 ` "load/\\\"https:\\/\\/s3-eu-west-1.amazonaws.com\\/1.svg\\\"  "`},
	// invalid input, found in apache log, -> workaround
	{` "load/\\\\"https:\\/\\/s3-eu-west-1.amazonaws.com\\/1.svg\\\\"  "`,
	 ` "load/\\\\\"https:\\/\\/s3-eu-west-1.amazonaws.com\\/1.svg\\\\\"  "`},
}

func TestSimple(t *testing.T) {
	for _, tt := range esctests {
		out := string(Unescape([]byte(tt.in)))
		if out != tt.out {
			t.Errorf("FAIL: %-10s --> %-10s, want %s", tt.in, out, tt.out)
		} else {
			t.Logf("OK:   %-10s --> %-10s", tt.in, out)
		}
	}
}
