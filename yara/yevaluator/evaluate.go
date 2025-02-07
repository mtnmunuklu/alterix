package yevaluator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/VirusTotal/gyp/ast"
	"github.com/mtnmunuklu/alterix/yara"
)

type RuleEvaluator struct {
	*ast.Rule
	config        []yara.Config       // Additional configuration options to use when evaluating the rule
	fieldmappings map[string][]string // A compiled mapping from rule fieldnames to possible event fieldnames
}

// ForRule constructs a new RuleEvaluator with the given Yara rule and evaluation options.
// It applies any provided options to the new RuleEvaluator and returns it.
func ForRule(rule *ast.Rule, options ...Option) *RuleEvaluator {
	e := &RuleEvaluator{Rule: rule}
	for _, option := range options {
		option(e)
	}
	return e
}

// Result represents the evaluation result of a Yara rule.
type Result struct {
	MetaResults     map[string]string
	StringsResults  map[string]string // The map of strings identifiers to their result values
	ConditionResult string            // The map of condition indices to their result values
	QueryResult     string            // The map of query indices to their result values
}

// This function returns a Result object containing the evaluation results for the yara rule.
func (rule RuleEvaluator) Alters() (Result, error) {
	result := Result{
		MetaResults:    make(map[string]string),
		StringsResults: make(map[string]string),
	}

	for _, meta := range rule.Meta {
		var metaValue strings.Builder
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

	result.ConditionResult = processConditionResult(condition.String(), result.StringsResults)

	result.QueryResult = "sourcetype='*' eql select * from _source_ where " + result.ConditionResult

	return result, nil
}

func processConditionResult(condition string, stringsResults map[string]string) string {
	keys := make([]string, 0, len(stringsResults))
	for key := range stringsResults {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j]) // Uzunluk sırasına göre azalan.
	})

	for _, key := range keys {
		if strings.Contains(condition, "$"+key) {
			condition = strings.ReplaceAll(condition, "$"+key, stringsResults[key])
		}
	}

	return condition
}
