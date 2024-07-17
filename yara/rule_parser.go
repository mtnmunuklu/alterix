package yara

import (
	"bytes"

	"github.com/VirusTotal/gyp/ast"
	"github.com/VirusTotal/gyp/parser"
)

// ParseRule parses a YARA rule from the provided byte slice.
func ParseRule(input []byte) (rs *ast.RuleSet, err error) {
	return parser.Parse((bytes.NewBuffer(input)))
}

// ParseString parses a YARA rule from the provided string.
func ParseString(s string) (*ast.RuleSet, error) {
	return ParseRule([]byte(s))
}
