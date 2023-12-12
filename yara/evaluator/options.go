package evaluator

import (
	"context"

	"github.com/mtnmunuklu/alterix/yara"
)

// Option is a function that takes a RuleEvaluator pointer and modifies its configuration
type Option func(*RuleEvaluator)

// WithPlaceholderExpander returns an Option that sets the provided function as the placeholder expander for the RuleEvaluator.
// The placeholder expander is used to expand any placeholders that might be present in the Sigma rule before evaluation.
// The provided function should take a context and a placeholder name and return a slice of strings that replace the placeholder in the Sigma rule.
// If an error occurs during the expansion process, the function should return an error.
func WithPlaceholderExpander(f func(ctx context.Context, placeholderName string) ([]string, error)) Option {
	return func(e *RuleEvaluator) {
		e.expandPlaceholder = f
	}
}

// WithConfig returns an Option that sets the provided Sigma configs to the RuleEvaluator.
// The configs are used to initialize the RuleEvaluator, which creates field mappings and indexes for efficient evaluation of Sigma rules.
// The configs should be provided in the order of precedence, and the function will append them to the RuleEvaluator's config slice.
// After the configs are set, the function will recalculate the RuleEvaluator's indexes and field mappings.
func WithConfig(config ...yara.Config) Option {
	return func(e *RuleEvaluator) {
		// TODO: assert that the configs are in the correct order
		e.config = append(e.config, config...)
		e.calculateFieldMappings()
	}
}
