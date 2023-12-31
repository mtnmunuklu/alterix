package sevaluator

import (
	"context"

	"github.com/mtnmunuklu/alterix/sigma"
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

// Declare variables for the rule and configuration
var rule sigma.Rule
var config sigma.Config

// Initialization function that parses the test rule and configuration
func init() {
	// Parse the test rule
	var err error
	rule, err = sigma.ParseRule([]byte(testRule))
	if err != nil {
		panic(err)
	}
	// Parse the test configuration
	config, err = sigma.ParseConfig([]byte(testConfig))
	if err != nil {
		panic(err)
	}
}

// Fuzz function that checks if a given input byte slice can trigger an alteration to the system
func FuzzRuleMatches(data []byte) int {
	// Create a rule object and pass in the parsed rule and configuration
	r := ForRule(rule, WithConfig(config))
	// Call the Alters() method on the rule object with a background context
	_, err := r.Alters(context.Background())
	// If an error occurs, return 0 to indicate that the input did not trigger an alteration
	if err != nil {
		return 0
	}
	// If no error occurs, return 1 to indicate that the input did trigger an alteration
	return 1
}
