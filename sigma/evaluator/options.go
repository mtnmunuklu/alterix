package evaluator

import (
	"context"

	"Alterix/sigma"
)

type Option func(*RuleEvaluator)

func WithPlaceholderExpander(f func(ctx context.Context, placeholderName string) ([]string, error)) Option {
	return func(e *RuleEvaluator) {
		e.expandPlaceholder = f
	}
}

func WithConfig(config ...sigma.Config) Option {
	return func(e *RuleEvaluator) {
		// TODO: assert that the configs are in the correct order
		e.config = append(e.config, config...)
		e.calculateIndexes()
		e.calculateFieldMappings()
	}
}
