package sevaluator

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/mtnmunuklu/alterix/sigma"
	"github.com/mtnmunuklu/alterix/sigma/sevaluator/modifiers"
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
		// if the number of searches is greater than 1, add "("
		if !isTopLevel && len(rule.Detection.Searches) > 1 {
			conditionResult = append(conditionResult, "(")
		}
		// iterate through all the search expressions and add 'or' between them
		for name := range rule.Detection.Searches {
			// If the search expression name matches the pattern, and it's not the first one, and the last element is not "and", "or", or "(", then add " or " to the condition result
			if len(conditionResult) > 0 {
				lastElement := conditionResult[len(conditionResult)-1]
				if lastElement != "and" && lastElement != "or" && lastElement != "(" {
					conditionResult = append(conditionResult, " or ")
				}
			}
			// evaluate the nested search expression
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}
		// if the number of searches is greater than 1, add ")"
		if !isTopLevel && len(rule.Detection.Searches) > 1 {
			conditionResult = append(conditionResult, ")")
		}
		return conditionResult

	case sigma.OneOfPattern:
		var matchingSearches []string
		// Iterate over the search expressions in the rule's searches
		for name := range rule.Detection.Searches {
			// Check if the search expression name matches the pattern
			matchesPattern, _ := path.Match(s.Pattern, name)
			if matchesPattern {
				// If the search expression name matches the pattern, add it to the matchingSearches slice
				matchingSearches = append(matchingSearches, name)
			}
		}

		numMatchingSearches := len(matchingSearches)
		// If there are more than one matching search expressions, add an opening parenthesis to the condition result
		if !isTopLevel && numMatchingSearches > 1 {
			conditionResult = append(conditionResult, "(")
		}

		// Iterate over the matching search expressions
		for i, name := range matchingSearches {
			if i > 0 {
				lastElement := conditionResult[len(conditionResult)-1]
				// If the last element in the condition result is not "and", "or", or "(", add " or " to the condition result
				if lastElement != "and" && lastElement != "or" && lastElement != "(" {
					conditionResult = append(conditionResult, " or ")
				}
			}
			// Evaluate the search expression and append its result to the condition result
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}

		// If there are more than one matching search expressions, add a closing parenthesis to the condition result
		if !isTopLevel && numMatchingSearches > 1 {
			conditionResult = append(conditionResult, ")")
		}

		return conditionResult

	case sigma.AllOfThem:
		// if the number of searches is greater than 1, add "("
		if !isTopLevel && len(rule.Detection.Searches) > 1 {
			conditionResult = append(conditionResult, "(")
		}
		// iterate over all search expressions in the rule's searches
		for name := range rule.Detection.Searches {
			// If the search expression name matches the pattern, and it's not the first one, and the last element is not "and", "or", or "(", then add " or " to the condition result
			if len(conditionResult) > 0 {
				lastElement := conditionResult[len(conditionResult)-1]
				if lastElement != "and" && lastElement != "or" && lastElement != "(" {
					conditionResult = append(conditionResult, " and ")
				}
			}
			// recursively evaluate the search expression and append its result to the condition result
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}
		// if the number of searches is greater than 1, add ")"
		if !isTopLevel && len(rule.Detection.Searches) > 1 {
			conditionResult = append(conditionResult, ")")
		}
		return conditionResult

	case sigma.AllOfPattern:
		var matchingSearches []string
		// Iterate over the search expressions in the rule's searches
		for name := range rule.Detection.Searches {
			// Check if the search expression name matches the pattern
			matchesPattern, _ := path.Match(s.Pattern, name)
			if matchesPattern {
				// If the search expression name matches the pattern, add it to the matchingSearches slice
				matchingSearches = append(matchingSearches, name)
			}
		}

		numMatchingSearches := len(matchingSearches)
		// If there are more than one matching search expressions, add an opening parenthesis to the condition result
		if !isTopLevel && numMatchingSearches > 1 {
			conditionResult = append(conditionResult, "(")
		}

		// Iterate over the matching search expressions
		for i, name := range matchingSearches {
			if i > 0 {
				lastElement := conditionResult[len(conditionResult)-1]
				// If the last element in the condition result is not "and", "or", or "(", add " or " to the condition result
				if lastElement != "and" && lastElement != "or" && lastElement != "(" {
					conditionResult = append(conditionResult, " and ")
				}
			}
			// Evaluate the search expression and append its result to the condition result
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}

		// If there are more than one matching search expressions, add a closing parenthesis to the condition result
		if !isTopLevel && numMatchingSearches > 1 {
			conditionResult = append(conditionResult, ")")
		}

		return conditionResult
	}
	panic(fmt.Sprintf("unhandled node type %T", search))
}

func (rule RuleEvaluator) evaluateSearch(ctx context.Context, search sigma.Search) ([]string, error) {
	var filters []string

	if len(search.Keywords) > 0 {
		joined := strings.Join(search.Keywords, " OR ")
		filter := fmt.Sprintf("Query('%s')", joined)
		filters = append(filters, filter)
		return filters, nil
	}

	if len(search.EventMatchers) == 0 {
		return filters, nil
	}

	for _, eventMatcher := range search.EventMatchers {
		for _, fieldMatcher := range eventMatcher {
			allValuesMustMatch := len(fieldMatcher.Modifiers) > 0 && fieldMatcher.Modifiers[len(fieldMatcher.Modifiers)-1] == "all"
			fieldModifiers := fieldMatcher.Modifiers
			if allValuesMustMatch {
				fieldModifiers = fieldModifiers[:len(fieldModifiers)-1]
			}

			comparator, err := modifiers.GetComparator(fieldModifiers...)
			if rule.caseSensitive {
				comparator, err = modifiers.GetComparatorCaseSensitive(fieldModifiers...)
			}
			if err != nil {
				return filters, err
			}

			matcherValues, err := rule.getMatcherValues(ctx, fieldMatcher)
			if err != nil {
				return filters, err
			}

			targetFields := []string{fieldMatcher.Field}
			if len(rule.fieldmappings[fieldMatcher.Field]) > 0 {
				targetFields = rule.fieldmappings[fieldMatcher.Field]
			}

			filter, err := rule.matcherMatchesValues(matcherValues, targetFields, comparator, allValuesMustMatch)
			if err != nil {
				return filters, err
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
		case nil:
			value = "null"
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
func (rule *RuleEvaluator) matcherMatchesValues(matcherValues []string, fields []string, comparator modifiers.ComparatorFunc, allValuesMustMatch bool) (string, error) {
	var filters []string
	for i, field := range fields {
		var subFilters []string
		for j, value := range matcherValues {
			// compare field and value using the provided comparator function
			filter, err := comparator(field, value)
			if err != nil {
				return "", err
			}
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
		return "(" + strings.Join(filters, "") + ")", nil
	} else {
		// if there's only one field, filters can be added directly
		return strings.Join(filters, ""), nil
	}
}
