package evaluator

import (
	"fmt"
	"strings"
)

type valueComparator func(field string, matcherValue string) string

func baseComparator(field string, matcherValue string) string {
	switch {
	case matcherValue == "null":
		// special case: "null" should match the case where a field isn't present (and so actual is nil)
		return fmt.Sprintf("%v = ''", strings.ToLower(field))
	default:
		// The Sigma spec defines that by default comparisons are case-insensitive
		return fmt.Sprintf("%v = '%v'", strings.ToLower(field), strings.ToLower(matcherValue))
	}
}

type valueModifier func(next valueComparator) valueComparator

var modifiers = map[string]valueModifier{
	"contains": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			// The Sigma spec defines that by default comparisons are case-insensitive
			return fmt.Sprintf("%v like '%%%v%%'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	"endswith": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			// The Sigma spec defines that by default comparisons are case-insensitive
			return fmt.Sprintf("%v like '%%%v'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	"startswith": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			// The Sigma spec defines that by default comparisons are case-insensitive
			return fmt.Sprintf("%v like '%v%%'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	"base64": func(next valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v base64 '%v'", strings.ToLower(field), matcherValue)
		}
	},
	"re": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v re '%v'", strings.ToLower(field), matcherValue)
		}
	},
	"cidr": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v cidr '%v'", strings.ToLower(field), matcherValue)
		}
	},
	"gt": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v > '%v'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	"gte": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v >= '%v'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	"lt": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v < '%v'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
	"lte": func(_ valueComparator) valueComparator {
		return func(field string, matcherValue string) string {
			return fmt.Sprintf("%v <= '%v'", strings.ToLower(field), strings.ToLower(matcherValue))
		}
	},
}
