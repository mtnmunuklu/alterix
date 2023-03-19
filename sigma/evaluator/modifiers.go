package evaluator

import (
	"fmt"
	"strings"
)

// valueComparator is a function that compares a field in an event to a value using a specified comparison method
type valueComparator func(field string, matcherValue string) string

// baseComparator is the default comparison method used by Sigma rules, which performs a case-insensitive string comparison
func baseComparator(field string, matcherValue string) string {
	switch {
	case matcherValue == "null":
		// The "null" value is treated as a special case and is used to match when a field is not present in the event
		return fmt.Sprintf("%v = ''", strings.ToLower(field))
	default:
		// Perform a case-insensitive string comparison
		return fmt.Sprintf("%v = '%v'", strings.ToLower(field), strings.ToLower(matcherValue))
	}
}

// valueModifier is a function that modifies a valueComparator function by wrapping it in additional logic
type valueModifier func(next valueComparator) valueComparator

// modifiers is a map of valueModifier functions that define various ways to modify a valueComparator function
var modifiers = map[string]valueModifier{
	// The "contains" modifier matches when the field contains the specified value (case-insensitive)
	"contains": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v like '%%%v%%'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	// The "endswith" modifier matches when the field ends with the specified value (case-insensitive)
	"endswith": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v like '%%%v'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	// The "startswith" modifier matches when the field starts with the specified value (case-insensitive)
	"startswith": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v like '%v%%'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	// The "base64" modifier matches when the field matches the specified value encoded in Base64
	"base64": func(next valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v base64 '%v'", strings.ToLower(field), matcherValue)
		}
	},
	// The "re" modifier matches when the field matches the specified regular expression
	"re": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v re '%v'", strings.ToLower(field), matcherValue)
		}
	},
	// The "cidr" modifier matches when the field is an IP address that matches the specified CIDR range
	"cidr": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v cidr '%v'", strings.ToLower(field), matcherValue)
		}
	},
	// The "gt" modifier matches when the field is greater than the specified value (case-insensitive)
	"gt": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v > '%v'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	// The "gte" modifier matches when the field is greater than or equal to the specified value (case-insensitive)
	"gte": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v >= '%v'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	// The "lt" modifier matches when the field is less than the specified value (case-insensitive)
	"lt": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v < '%v'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	// The "lte" modifier matches when the field is less than or equal to the specified value (case-insensitive)
	"lte": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v <= '%v'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
}
