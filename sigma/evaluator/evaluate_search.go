package evaluator

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/mtnmunuklu/alterix/sigma"
)

// evaluateSearchExpression evaluates a Sigma search expression recursively and returns a string representation of the search condition.
func (rule RuleEvaluator) evaluateSearchExpression(search sigma.SearchExpr, conditionResult []string, isTopLevel bool) []string {
	// evaluate search expressions using a switch statement
	switch s := search.(type) {
	// if the search is an 'and' operation
	case sigma.And:
		// if not top level and more than 1 condition, add '(' to conditionResult
		if !isTopLevel && len(s) > 1 {
			conditionResult = append(conditionResult, "(")
		}
		// iterate through the conditions and add 'and' between them
		for i, node := range s {
			if i > 0 {
				conditionResult = append(conditionResult, " and ")
			}
			// evaluate the nested search expression
			conditionResult = rule.evaluateSearchExpression(node, conditionResult, false)
		}
		// if not top level and more than 1 condition, add ')' to conditionResult
		if !isTopLevel && len(s) > 1 {
			conditionResult = append(conditionResult, ")")
		}
		return conditionResult

	// if the search is an 'or' operation
	case sigma.Or:
		// if not top level and more than 1 condition, add '(' to conditionResult
		if !isTopLevel && len(s) > 1 {
			conditionResult = append(conditionResult, "(")
		}
		// iterate through the conditions and add 'or' between them
		for i, node := range s {
			if i > 0 {
				conditionResult = append(conditionResult, " or ")
			}
			// evaluate the nested search expression
			conditionResult = rule.evaluateSearchExpression(node, conditionResult, false)
		}
		// if not top level and more than 1 condition, add ')' to conditionResult
		if !isTopLevel && len(s) > 1 {
			conditionResult = append(conditionResult, ")")
		}
		return conditionResult

	// if the search is a 'not' operation
	case sigma.Not:
		// add 'not' to conditionResult
		conditionResult = append(conditionResult, " not ")
		// evaluate the nested search expression
		conditionResult = rule.evaluateSearchExpression(s.Expr, conditionResult, false)
		return conditionResult

	// if the search is an identifier
	case sigma.SearchIdentifier:
		// add the identifier name to conditionResult
		conditionResult = append(conditionResult, s.Name)
		return conditionResult

	// if the search is 'one of them'
	case sigma.OneOfThem:
		// iterate through all the search expressions and add 'or' between them
		for name := range rule.Detection.Searches {
			if len(conditionResult) > 0 {
				conditionResult = append(conditionResult, " or ")
			}
			// evaluate the nested search expression
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}
		return conditionResult

	case sigma.OneOfPattern:
		// iterate over all search expressions in the rule's searches
		for name := range rule.Detection.Searches {
			// check if the search expression name matches the pattern
			matchesPattern, _ := path.Match(s.Pattern, name)
			if !matchesPattern {
				// if the search expression name does not match the pattern, skip to the next one
				continue
			}
			// if the search expression name matches the pattern and it's not the first one, add " or " to the condition result
			if len(conditionResult) > 0 {
				conditionResult = append(conditionResult, " or ")
			}
			// recursively evaluate the search expression and append its result to the condition result
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}
		return conditionResult

	case sigma.AllOfThem:
		// iterate over all search expressions in the rule's searches
		for name := range rule.Detection.Searches {
			// if it's not the first search expression, add " and " to the condition result
			if len(conditionResult) > 0 {
				conditionResult = append(conditionResult, " and ")
			}
			// recursively evaluate the search expression and append its result to the condition result
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}
		return conditionResult

	case sigma.AllOfPattern:
		// iterate over all search expressions in the rule's searches
		for name := range rule.Detection.Searches {
			// check if the search expression name matches the pattern
			matchesPattern, _ := path.Match(s.Pattern, name)
			if !matchesPattern {
				// if the search expression name does not match the pattern, skip to the next one
				continue
			}
			// if the search expression name matches the pattern and it's not the first one, add " and " to the condition result
			if len(conditionResult) > 0 {
				conditionResult = append(conditionResult, " and ")
			}
			// recursively evaluate the search expression and append its result to the condition result
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}
		return conditionResult
	}
	panic(fmt.Sprintf("unhandled node type %T", search))
}

// The evaluateSearch function takes a sigma.Search object and evaluates it, returning a slice of filter strings or an error.
func (rule RuleEvaluator) evaluateSearch(ctx context.Context, search sigma.Search) ([]string, error) {
	var filters []string

	if len(search.Keywords) > 0 {
		return filters, fmt.Errorf("keywords unsupported")
	}

	if len(search.EventMatchers) == 0 {
		// degenerate case (but common for logsource conditionResults)
		return filters, nil
	}

	// A Search is a series of EventMatchers (usually one)
	// Each EventMatchers is a series of "does this field match this value" conditionResults
	// all fields need to match for an EventMatcher to match, but only one EventMatcher needs to match for the Search to evaluate to true
	for _, eventMatcher := range search.EventMatchers {
		for _, fieldMatcher := range eventMatcher {
			// A field matcher can specify multiple values to match against
			// either the field should match all of these values or it should match any of them
			allValuesMustMatch := false
			fieldModifiers := fieldMatcher.Modifiers
			if len(fieldMatcher.Modifiers) > 0 && fieldModifiers[len(fieldModifiers)-1] == "all" {
				allValuesMustMatch = true
				fieldModifiers = fieldModifiers[:len(fieldModifiers)-1]
			}

			// field matchers can specify modifiers (FieldName|modifier1|modifier2) which change the matching behaviour
			comparator := baseComparator
			for _, name := range fieldModifiers {
				if modifiers[name] == nil {
					return filters, fmt.Errorf("unsupported modifier %s", name)
				}
				comparator = modifiers[name](comparator)
			}

			matcherValues, err := rule.getMatcherValues(ctx, fieldMatcher)
			if err != nil {
				return filters, err
			}

			var filter string
			if len(rule.fieldmappings[fieldMatcher.Field]) == 0 {
				// If there are no field mappings defined, only the specified field is checked
				filter = rule.matcherMatchesValues(matcherValues, []string{fieldMatcher.Field}, comparator, allValuesMustMatch)
			} else {
				// If there are field mappings defined, they are used to check multiple fields
				filter = rule.matcherMatchesValues(matcherValues, rule.fieldmappings[fieldMatcher.Field], comparator, allValuesMustMatch)
			}

			filters = append(filters, filter)
		}
	}

	return filters, nil
}

// getMatcherValues function retrieves the matching values for a field matcher.
func (rule *RuleEvaluator) getMatcherValues(ctx context.Context, matcher sigma.FieldMatcher) ([]string, error) {
	// Initialize an empty array for the matching values.
	matcherValues := []string{}

	// Loop through all abstract values for the matcher.
	for _, abstractValue := range matcher.Values {
		value := ""

		// Check the type of the abstract value and convert it to a string if it's a scalar value.
		switch abstractValue := abstractValue.(type) {
		case string:
			value = abstractValue
		case int, float32, float64, bool:
			value = fmt.Sprintf("%v", abstractValue)
		default:
			return nil, fmt.Errorf("expected scalar field matching value got: %v (%T)", abstractValue, abstractValue)
		}

		// If the value is a placeholder, expand it to its corresponding values using the provided expandPlaceholder function.
		if strings.HasPrefix(value, "%") && strings.HasSuffix(value, "%") {
			if rule.expandPlaceholder == nil {
				return nil, fmt.Errorf("can't expand %s, no placeholder expander function defined", value)
			}
			placeholderValues, err := rule.expandPlaceholder(ctx, value)
			if err != nil {
				return nil, fmt.Errorf("failed to expand placeholder: %w", err)
			}
			// Append the placeholderValues to the matcherValues array.
			matcherValues = append(matcherValues, placeholderValues...)
		} else {
			// Append the scalar value to the matcherValues array.
			matcherValues = append(matcherValues, value)
		}
	}
	// Return the array of matching values and nil for the error.
	return matcherValues, nil
}

// matcherMatchesValues takes a list of values to match against a list of fields,
// a comparator function to compare values and fields, and a boolean indicating whether all values must match or any of them.
// It returns a string representing a filter that can be used to match events with the specified fields and values.
func (rule *RuleEvaluator) matcherMatchesValues(matcherValues []string, fields []string, comparator valueComparator, allValuesMustMatch bool) string {
	var filters []string
	for i, field := range fields {
		var subFilters []string
		for j, matcherValue := range matcherValues {
			// compare field and matcherValue using the provided comparator function
			filter := comparator(field, matcherValue)
			if j == 0 {
				// first match value should be added directly to subFilters
				subFilters = append(subFilters, filter)
			} else if allValuesMustMatch {
				// if all values must match, add " and " between subfilters
				subFilters = append(subFilters, " and ", filter)
			} else {
				// if any value can match, add " or " between subfilters
				subFilters = append(subFilters, " or ", filter)
			}
		}
		if len(matcherValues) > 1 {
			// if there are multiple matcher values, wrap subFilters in parentheses to keep operator precedence
			filters = append(filters, "("+strings.Join(subFilters, "")+")")
		} else {
			// if there's only one matcher value, subFilters can be added directly to filters
			filters = append(filters, subFilters...)
		}
		if i < len(fields)-1 {
			// if there are multiple fields, add " or " between them
			filters = append(filters, " or ")
		}
	}
	if len(fields) > 1 {
		// if there are multiple fields, wrap filters in parentheses to keep operator precedence
		return "(" + strings.Join(filters, "") + ")"
	} else {
		// if there's only one field, filters can be added directly
		return strings.Join(filters, "")
	}
}
