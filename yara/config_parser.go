package yara

import (
	"gopkg.in/yaml.v3"
)

// Config is a struct that defines the Yara configuration
type Config struct {
	Title         string // A short description of what this configuration does
	Order         int    // Defines the order of expansion when multiple config files are applicable
	FieldMappings map[string]FieldMapping
	Placeholders  map[string][]interface{} // Defines values for placeholders that might appear in Yara rules
}

// FieldMapping is a struct that defines the target fields to be matched in Yara rules
type FieldMapping struct {
	TargetNames []string // The name(s) that appear in the events being matched
}

// UnmarshalYAML is a custom method for unmarshaling YAML data into FieldMapping
func (f *FieldMapping) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		// If the YAML value is a scalar (single value), set it as the only element in the slice
		f.TargetNames = []string{value.Value}

	case yaml.SequenceNode:
		// If the YAML value is a sequence (list), decode it into a slice
		var values []string
		err := value.Decode(&values)
		if err != nil {
			return err
		}
		f.TargetNames = values
	}
	return nil
}

// ParseConfig takes a byte slice of YAML data and returns a Config struct or an error if unmarshaling fails
func ParseConfig(contents []byte) (Config, error) {
	config := Config{}
	return config, yaml.Unmarshal(contents, &config)
}
