package evaluator

// RelevantToIndex calculates whether this rule is applicable to a given index.
// Only applicable if a config file has been loaded otherwise it always returns false.
func (rule *RuleEvaluator) calculateIndexes() {
	if rule.config == nil {
		return
	}

	var indexes []string

	category := rule.Logsource.Category
	product := rule.Logsource.Product
	service := rule.Logsource.Service

	for _, config := range rule.config {
		matched := false
		for _, logsource := range config.Logsources {
			// If this mapping is not relevant, skip it
			switch {
			case logsource.Category != "" && logsource.Category != category:
				continue
			case logsource.Product != "" && logsource.Product != product:
				continue
			case logsource.Service != "" && logsource.Service != service:
				continue
			}

			matched = true
			// LogsourceMappings can specify rewrite rules that change the effective Category, Product, and Service of a rule.
			// These then get interpreted by later configs.
			if logsource.Rewrite.Category != "" {
				rule.Logsource.Category = logsource.Rewrite.Category
			}
			if logsource.Rewrite.Product != "" {
				rule.Logsource.Product = logsource.Rewrite.Product
			}
			if logsource.Rewrite.Service != "" {
				rule.Logsource.Service = logsource.Rewrite.Service
			}

			// If the mapping has indexes then append them to the possible ones
			indexes = append(indexes, logsource.Index...)

			// If the mapping declares conditions then AND them with the current one
			rule.indexConditions = append(rule.indexConditions, logsource.Conditions)
		}

		if !matched && config.DefaultIndex != "" {
			indexes = append(indexes, config.DefaultIndex)
		}
	}

	rule.indexes = indexes
}

func (rule RuleEvaluator) Indexes() []string {
	return rule.indexes
}
