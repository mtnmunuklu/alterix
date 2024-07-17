package ievaluator

import (
	"github.com/mtnmunuklu/alterix/ioc"
)

// Option is a function that takes a IOCEvaluator pointer and modifies its configuration
type Option func(*IOCEvaluator)

// WithConfig returns an Option that sets the provided IOC configs to the IOCEvaluator.
func WithConfig(config ...ioc.Config) Option {
	return func(e *IOCEvaluator) {
		// TODO: assert that the configs are in the correct order
		e.config = append(e.config, config...)
		e.calculateFieldMappings()
	}
}
