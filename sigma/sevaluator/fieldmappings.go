package sevaluator

// calculateFieldMappings compiles a mapping from the rule fieldnames to possible event fieldnames
func (rule *RuleEvaluator) calculateFieldMappings() {
	// If no config is supplied, no field mapping is needed.
	if rule.config == nil {
		return
	}

	// mappings is a map from rule fieldnames to possible event fieldnames.
	mappings := map[string][]string{}

	// Loop through each config that is supplied.
	for _, config := range rule.config {
		// For each field in the config, add the mapping target names to the mappings.
		for field, mapping := range config.FieldMappings {
			// TODO: trim duplicates and only care about fields that are actually checked by this rule
			mappings[field] = append(mappings[field], mapping.TargetNames...)
		}
	}

	// Set the field mappings of the RuleEvaluator to the compiled mappings.
	rule.fieldmappings = mappings
}
