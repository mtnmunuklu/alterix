package evaluator

import (
	"context"
	"fmt"
	"strings"

	"Alterix/sigma"
)

type RuleEvaluator struct {
	sigma.Rule
	config          []sigma.Config
	indexes         []string            // the list of indexes that this rule should be applied to. Computed from the Logsource field in the rule and any config that's supplied.
	indexConditions []sigma.Search      // any field-value conditions that need to match for this rule to apply to events from []indexes
	fieldmappings   map[string][]string // a compiled mapping from rule fieldnames to possible event fieldnames

	expandPlaceholder func(ctx context.Context, placeholderName string) ([]string, error)
}

func ForRule(rule sigma.Rule, options ...Option) *RuleEvaluator {
	e := &RuleEvaluator{Rule: rule}
	for _, option := range options {
		option(e)
	}
	return e
}

type Result struct {
	SearchResults      map[string][]string
	ConditionResults   map[int][]string
	AggregationResults map[int]string
	QueryResults       map[int]string
}

func (rule RuleEvaluator) Alters(ctx context.Context) (Result, error) {
	result := Result{
		SearchResults:      make(map[string][]string),
		ConditionResults:   make(map[int][]string),
		AggregationResults: make(map[int]string),
		QueryResults:       make(map[int]string),
	}
	for identifier, search := range rule.Detection.Searches {
		var err error
		result.SearchResults[identifier], err = rule.evaluateSearch(ctx, search)
		if err != nil {
			return Result{}, fmt.Errorf("error evaluating search %s: %w", identifier, err)
		}
	}

	for conditionIndex, condition := range rule.Detection.Conditions {
		result.ConditionResults[conditionIndex] = rule.evaluateSearchExpression(condition.Search, []string{}, true)
		if condition.Aggregation != nil {
			var err error
			result.AggregationResults[conditionIndex], err = rule.evaluateAggregationExpression(ctx, conditionIndex, condition.Aggregation)
			if err != nil {
				return Result{}, err
			}
		}
	}
	for i, conditionResult := range result.ConditionResults {
		conditionList := make([]string, 0, len(conditionResult))
		for _, condition := range conditionResult {
			if value, ok := result.SearchResults[condition]; ok {
				if len(value) > 1 {
					conditionList = append(conditionList, "("+strings.Join(value, " and ")+")")
				} else {
					conditionList = append(conditionList, strings.Join(value, ""))
				}

			} else {
				conditionList = append(conditionList, condition)
			}
		}
		if result.AggregationResults[i] != "" {
			aggregationResult := strings.Split(result.AggregationResults[i], "|")
			for j, aggregation := range aggregationResult {
				if j == 0 {
					result.QueryResults[i] = aggregation + " where " + strings.Join(conditionList, " ")
				} else {
					result.QueryResults[i] += " " + aggregation
				}
			}
		} else {
			result.QueryResults[i] = "where " + strings.Join(conditionList, " ")
		}
		if rule.Logsource.Product != "" && rule.Logsource.Service != "" {
			result.QueryResults[i] = fmt.Sprintf("sourcetype='%v' %v", rule.Logsource.Product+"-"+rule.Logsource.Service, result.QueryResults[i])
		} else if rule.Logsource.Product != "" && rule.Logsource.Service == "" {
			result.QueryResults[i] = fmt.Sprintf("sourcetype='%v' %v", rule.Logsource.Product+"-*", result.QueryResults[i])
		}
	}

	for _, queryResult := range result.QueryResults {
		fmt.Printf("%v\n", queryResult)
	}
	return result, nil
}
