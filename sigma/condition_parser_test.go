package sigma

import (
	"reflect"
	"testing"
)

// TestParseCondition is a test function that tests the ParseCondition function
func TestParseCondition(t *testing.T) {
	// tt is a slice of test cases that includes input conditions and their expected outputs
	tt := []struct {
		condition string
		parsed    Condition
	}{
		// the first test case expects an And expression with two SearchIdentifier expressions
		{"a and b", Condition{Search: And{SearchIdentifier{"a"}, SearchIdentifier{"b"}}}},
		// the second test case expects an Or expression with two SearchIdentifier expressions
		{"a or b", Condition{Search: Or{SearchIdentifier{"a"}, SearchIdentifier{"b"}}}},
		// the third test case expects an Or expression with an And expression and a SearchIdentifier expression
		{"a and b or c", Condition{Search: Or{And{SearchIdentifier{"a"}, SearchIdentifier{"b"}}, SearchIdentifier{"c"}}}},
		// the fourth test case expects an Or expression with a SearchIdentifier expression and an And expression
		{"a or b and c", Condition{Search: Or{SearchIdentifier{"a"}, And{SearchIdentifier{"b"}, SearchIdentifier{"c"}}}}},
		// the fifth test case expects an And expression with three SearchIdentifier expressions
		{"a and b and c", Condition{Search: And{SearchIdentifier{"a"}, SearchIdentifier{"b"}, SearchIdentifier{"c"}}}},
		// the sixth test case expects a SearchIdentifier expression and a Count aggregation expression with a GreaterThan comparison
		{"a | count(b) > 0", Condition{Search: SearchIdentifier{"a"}, Aggregation: Comparison{Func: Count{Field: "b"}, Op: GreaterThan, Threshold: 0}}},
		// the seventh test case expects a SearchIdentifier expression and a Count aggregation expression with a GreaterThanEqual comparison
		{"a | count(b) >= 0", Condition{Search: SearchIdentifier{"a"}, Aggregation: Comparison{Func: Count{Field: "b"}, Op: GreaterThanEqual, Threshold: 0}}},
		// the eighth test case expects an And expression with two SearchIdentifier expressions
		{"note and pad", Condition{Search: And{SearchIdentifier{"note"}, SearchIdentifier{"pad"}}}},
	}

	// iterate over each test case and execute the test
	for _, tc := range tt {
		t.Run(tc.condition, func(t *testing.T) {
			// parse the condition
			condition, err := ParseCondition(tc.condition)
			if err != nil {
				// if an error occurred, fail the test
				t.Fatal(err)
			}
			// compare the parsed condition with the expected output
			if !reflect.DeepEqual(condition, tc.parsed) {
				// if they are not equal, fail the test
				t.Fatalf("%+v not equal %+v", condition, tc.parsed)
			}
		})
	}
}
