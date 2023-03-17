package evaluator

import (
	"context"
	"fmt"
	"path"
	"strings"

	"Alterix/sigma"
)

func (rule RuleEvaluator) evaluateSearchExpression(search sigma.SearchExpr, conditionResult []string, isTopLevel bool) []string {
	switch s := search.(type) {
	case sigma.And:
		if !isTopLevel && len(s) > 1 {
			conditionResult = append(conditionResult, "(")
		}
		for i, node := range s {
			if i > 0 {
				conditionResult = append(conditionResult, " and ")
			}
			conditionResult = rule.evaluateSearchExpression(node, conditionResult, false)
		}
		if !isTopLevel && len(s) > 1 {
			conditionResult = append(conditionResult, ")")
		}
		return conditionResult

	case sigma.Or:
		if !isTopLevel && len(s) > 1 {
			conditionResult = append(conditionResult, "(")
		}
		for i, node := range s {
			if i > 0 {
				conditionResult = append(conditionResult, " or ")
			}
			conditionResult = rule.evaluateSearchExpression(node, conditionResult, false)
		}
		if !isTopLevel && len(s) > 1 {
			conditionResult = append(conditionResult, ")")
		}
		return conditionResult

	case sigma.Not:
		conditionResult = append(conditionResult, " not ")
		conditionResult = rule.evaluateSearchExpression(s.Expr, conditionResult, false)
		return conditionResult

	case sigma.SearchIdentifier:
		// If `s.Name` is not defined, this is always false
		conditionResult = append(conditionResult, s.Name)
		return conditionResult

	case sigma.OneOfThem:
		for name := range rule.Detection.Searches {
			if len(conditionResult) > 0 {
				conditionResult = append(conditionResult, " or ")
			}
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}
		return conditionResult

	case sigma.OneOfPattern:
		for name := range rule.Detection.Searches {
			// it's not possible for this call to error because the search expression parser won't allow this to contain invalid expressions
			matchesPattern, _ := path.Match(s.Pattern, name)
			if !matchesPattern {
				continue
			}
			if len(conditionResult) > 0 {
				conditionResult = append(conditionResult, " or ")
			}
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}
		return conditionResult

	case sigma.AllOfThem:
		for name := range rule.Detection.Searches {
			if len(conditionResult) > 0 {
				conditionResult = append(conditionResult, " and ")
			}
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}
		return conditionResult

	case sigma.AllOfPattern:
		for name := range rule.Detection.Searches {
			// it's not possible for this call to error because the search expression parser won't allow this to contain invalid expressions
			matchesPattern, _ := path.Match(s.Pattern, name)
			if !matchesPattern {
				continue
			}
			if len(conditionResult) > 0 {
				conditionResult = append(conditionResult, " and ")
			}
			conditionResult = rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, conditionResult, false)
		}
		return conditionResult
	}
	panic(fmt.Sprintf("unhandled node type %T", search))
}

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

				filter = rule.matcherMatchesValues(matcherValues, []string{fieldMatcher.Field}, comparator, allValuesMustMatch)
			} else {
				filter = rule.matcherMatchesValues(matcherValues, rule.fieldmappings[fieldMatcher.Field], comparator, allValuesMustMatch)
			}
			filters = append(filters, filter)
		}
	}

	return filters, nil
}

func (rule *RuleEvaluator) getMatcherValues(ctx context.Context, matcher sigma.FieldMatcher) ([]string, error) {
	matcherValues := []string{}
	for _, abstractValue := range matcher.Values {
		value := ""

		switch abstractValue := abstractValue.(type) {
		case string:
			value = abstractValue
		case int, float32, float64, bool:
			value = fmt.Sprintf("%v", abstractValue)
		default:
			return nil, fmt.Errorf("expected scalar field matching value got: %v (%T)", abstractValue, abstractValue)
		}

		if strings.HasPrefix(value, "%") && strings.HasSuffix(value, "%") {
			// expand placeholder to values
			if rule.expandPlaceholder == nil {
				return nil, fmt.Errorf("can't expand %s, no placeholder expander function defined", value)
			}
			placeholderValues, err := rule.expandPlaceholder(ctx, value)
			if err != nil {
				return nil, fmt.Errorf("failed to expand placeholder: %w", err)
			}
			matcherValues = append(matcherValues, placeholderValues...)
		} else {
			matcherValues = append(matcherValues, value)
		}
	}
	return matcherValues, nil
}

func (rule *RuleEvaluator) matcherMatchesValues(matcherValues []string, fields []string, comparator valueComparator, allValuesMustMatch bool) string {
	var filters []string
	for i, field := range fields {
		var subFilters []string
		for j, matcherValue := range matcherValues {
			filter := comparator(field, matcherValue)
			if j == 0 {
				subFilters = append(subFilters, filter)
			} else if allValuesMustMatch {
				subFilters = append(subFilters, " and ", filter)
			} else {
				subFilters = append(subFilters, " or ", filter)
			}
		}
		if len(matcherValues) > 1 {
			filters = append(filters, "("+strings.Join(subFilters, "")+")")
		} else {
			filters = append(filters, subFilters...)
		}
		if i < len(fields)-1 {
			filters = append(filters, " or ")
		}
	}
	if len(fields) > 1 {
		return "(" + strings.Join(filters, "") + ")"
	} else {
		return strings.Join(filters, "")
	}
}
