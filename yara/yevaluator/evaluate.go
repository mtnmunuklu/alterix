package yevaluator

import (
	"fmt"
	"strings"

	"github.com/VirusTotal/gyp/ast"
	"github.com/mtnmunuklu/alterix/yara"
)

// RuleEvaluator represents a rule evaluator that is capable of computing the search, condition, and query results of a Yara rule.
// It holds the rule configuration, search conditions, and field mappings necessary to apply the rule to log events and generate the query results.
type RuleEvaluator struct {
	*ast.Rule
	config        []yara.Config       // Additional configuration options to use when evaluating the rule
	fieldmappings map[string][]string // A compiled mapping from rule fieldnames to possible event fieldnames
}

// ForRule constructs a new RuleEvaluator with the given Sigma rule and evaluation options.
// It applies any provided options to the new RuleEvaluator and returns it.
func ForRule(rule *ast.Rule, options ...Option) *RuleEvaluator {
	e := &RuleEvaluator{Rule: rule}
	for _, option := range options {
		option(e)
	}
	return e
}

// Result represents the evaluation result of a Sigma rule.
// It contains the search, condition, aggregation, and query results of the rule evaluation.
type Result struct {
	MetaResults     map[string]string
	StringsResults  map[string]string // The map of strings identifiers to their result values
	ConditionResult string            // The map of condition indices to their result values
	QueryResult     string            // The map of query indices to their result values
}

// This function returns a Result object containing the evaluation results for the rule's Detection field.
// It uses the evaluateSearch, evaluateSearchExpression and evaluateAggregationExpression functions to compute the results.
func (rule RuleEvaluator) Alters() (Result, error) {
	result := Result{
		MetaResults:    make(map[string]string),
		StringsResults: make(map[string]string),
	}

	var metaValue strings.Builder
	for _, meta := range rule.Meta {
		var err error
		metaKey := meta.Key
		err = rule.evaluateMeta(&metaValue, meta.AsProto())
		if err != nil {
			return Result{}, fmt.Errorf("error evaluating meta %s: %w", metaKey, err)
		}
		result.MetaResults[metaKey] = metaValue.String()
	}

	for _, str := range rule.Strings {
		var filter strings.Builder
		var err error
		identifier := str.GetIdentifier()
		err = rule.evaluateStrings(&filter, identifier, str.AsProto())
		if err != nil {
			return Result{}, fmt.Errorf("error evaluating string %s: %w", identifier, err)
		}
		result.StringsResults[identifier] = filter.String()
	}

	var err error
	var condition strings.Builder
	err = rule.evaluateExpression(&condition, rule.Condition.AsProto())
	if err != nil {
		return Result{}, fmt.Errorf("error evaluating expression: %w", err)
	}

	result.ConditionResult = condition.String()
	for key, value := range result.StringsResults {
		if strings.Contains(result.ConditionResult, "$"+key) {
			result.ConditionResult = strings.ReplaceAll(result.ConditionResult, "$"+key, value)
		}
	}

	result.QueryResult = "sourcetype='*' eql select * from _source_ where _condition_ and " + result.ConditionResult

	return result, nil
}
