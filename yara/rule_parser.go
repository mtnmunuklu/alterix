package yara

import (
	"bytes"
	"io"

	"github.com/VirusTotal/gyp/ast"
	"github.com/VirusTotal/gyp/parser"
)

// Parse parses a YARA rule from the provided input source.
func ParseRule(input io.Reader) (rs *ast.RuleSet, err error) {
	return parser.Parse(input)
}

// ParseString parses a YARA rule from the provided string.
func ParseString(s string) (*ast.RuleSet, error) {
	return ParseRule(bytes.NewBufferString(s))
}

// ParseByte parses a YARA rule from the provided byte slice.
func ParseByte(input []byte) (rs *ast.RuleSet, err error) {
	return ParseRule(bytes.NewBuffer(input))
}
