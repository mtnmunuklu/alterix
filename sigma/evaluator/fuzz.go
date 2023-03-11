package evaluator

import (
	"context"

	"Alterix/sigma"
)

const testRule = `
id: TEST_RULE
detection:
  a:
    Foo|contains: bar
  b:
    Bar|endswith: baz
  condition: a and b
`

const testConfig = `
title: Test
logsources:
    test:
        product: test

fieldmappings:
    Foo: $.foo
    Bar: $.foobar.baz
`

var rule sigma.Rule
var config sigma.Config

func init() {
	var err error
	rule, err = sigma.ParseRule([]byte(testRule))
	if err != nil {
		panic(err)
	}
	config, err = sigma.ParseConfig([]byte(testConfig))
	if err != nil {
		panic(err)
	}
}

// Run with: go-fuzz-build --preserve "encoding/json" && go-fuzz
func FuzzRuleMatches(data []byte) int {
	r := ForRule(rule, WithConfig(config))
	_, err := r.Alters(context.Background())
	if err != nil {
		return 0
	}
	return 1
}
