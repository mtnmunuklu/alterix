package sevaluator

// The RelevantToIndex method determines whether the current rule is applicable to the given index.
// It returns false if a configuration file has not been loaded yet.
func (rule *RuleEvaluator) calculateIndexes() {
	if rule.config == nil {
		return
	}

	var indexes []string

	// Extract category, product, and service from the current logsource
	category := rule.Logsource.Category
	product := rule.Logsource.Product
	service := rule.Logsource.Service

	// Loop through all the configurations in the loaded config file
	for _, config := range rule.config {
		// Keep track of whether the rule has matched any logsource mappings in the config
		matched := false
		for _, logsource := range config.Logsources {
			// Check if the mapping is relevant to the current logsource
			switch {
			case logsource.Category != "" && logsource.Category != category:
				continue
			case logsource.Product != "" && logsource.Product != product:
				continue
			case logsource.Service != "" && logsource.Service != service:
				continue
			}
			// If the mapping is relevant, mark the rule as matched
			matched = true

			// If the mapping has specified a rewrite rule for category, product, or service, update the values in the current logsource
			if logsource.Rewrite.Category != "" {
				rule.Logsource.Category = logsource.Rewrite.Category
			}
			if logsource.Rewrite.Product != "" {
				rule.Logsource.Product = logsource.Rewrite.Product
			}
			if logsource.Rewrite.Service != "" {
				rule.Logsource.Service = logsource.Rewrite.Service
			}

			// Append any indexes specified in the mapping to the possible indexes for the current rule
			indexes = append(indexes, logsource.Index...)

			// If the mapping has specified conditions, AND them with the current ones
			rule.indexConditions = append(rule.indexConditions, logsource.Conditions)
		}

		// If the rule hasn't matched any mappings and a default index is specified in the config, use it
		if !matched && config.DefaultIndex != "" {
			indexes = append(indexes, config.DefaultIndex)
		}
	}

	// Set the possible indexes for the current rule
	rule.indexes = indexes
}

// The Indexes method returns the possible indexes for the current rule
func (rule RuleEvaluator) Indexes() []string {
	return rule.indexes
}
