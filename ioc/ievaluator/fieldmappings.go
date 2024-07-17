package ievaluator

// calculateFieldMappings compiles a mapping from the ioc fieldnames to possible event fieldnames
func (ioc *IOCEvaluator) calculateFieldMappings() {
	// If no config is supplied, no field mapping is needed.
	if ioc.config == nil {
		return
	}

	// mappings is a map from ioc fieldnames to possible event fieldnames.
	mappings := map[string][]string{}

	// Loop through each config that is supplied.
	for _, config := range ioc.config {
		// For each field in the config, add the mapping target names to the mappings.
		for field, mapping := range config.FieldMappings {
			// TODO: trim duplicates and only care about fields that are actually checked by this ioc
			mappings[field] = append(mappings[field], mapping.TargetNames...)
		}
	}

	// Set the field mappings of the RuleEvaluator to the compiled mappings.
	ioc.fieldmappings = mappings
}
