package yevaluator

import (
	"github.com/mtnmunuklu/alterix/yara"
)

// Option is a function that takes a RuleEvaluator pointer and modifies its configuration
type Option func(*RuleEvaluator)

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
