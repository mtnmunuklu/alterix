package sigma

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	// Required fields
	Title     string    // The title of the Sigma rule
	Logsource Logsource // The log source that the rule should be applied to
	Detection Detection // The detection logic of the rule

	// Optional fields
	ID          string        `yaml:",omitempty" json:",omitempty"` // The unique ID of the rule
	Related     []RelatedRule `yaml:",omitempty" json:",omitempty"` // Related rules, if any
	Status      string        `yaml:",omitempty" json:",omitempty"` // The status of the rule (e.g. "testing", "production")
	Description string        `yaml:",omitempty" json:",omitempty"` // A brief description of the rule
	Author      string        `yaml:",omitempty" json:",omitempty"` // The author of the rule
	Level       string        `yaml:",omitempty" json:",omitempty"` // The severity level of the rule (e.g. "low", "medium", "high")
	References  []string      `yaml:",omitempty" json:",omitempty"` // References related to the rule
	Tags        []string      `yaml:",omitempty" json:",omitempty"` // Tags that can be used to organize the rules

	// Any non-standard fields will end up in here
	AdditionalFields map[string]interface{} `yaml:",inline,omitempty" json:",inline,omitempty"` // Any additional fields in the YAML document
}

type RelatedRule struct {
	ID   string // The unique ID of the related rule
	Type string // The type of the related rule (e.g. "similar", "correlated", "superseded")
}

type Logsource struct {
	Category   string `yaml:",omitempty" json:",omitempty"` // The category of the log source
	Product    string `yaml:",omitempty" json:",omitempty"` // The product associated with the log source
	Service    string `yaml:",omitempty" json:",omitempty"` // The service associated with the log source
	Definition string `yaml:",omitempty" json:",omitempty"` // The definition of the log source

	// Any non-standard fields will end up in here
	AdditionalFields map[string]interface{} `yaml:",inline,omitempty" json:",inline,omitempty"` // Any additional fields in the YAML document
}

type Detection struct {
	Searches   map[string]Search `yaml:",inline" json:",inline"`       // Searches holds a map of search query strings and their corresponding configurations.
	Conditions Conditions        `yaml:"condition" json:"condition"`   // Conditions holds a slice of conditions to be checked for the detection to occur.
	Timeframe  time.Duration     `yaml:",omitempty" json:",omitempty"` // Timeframe specifies the time duration within which the detection must occur.
}

func (d *Detection) UnmarshalYAML(node *yaml.Node) error {
	// we need a custom unmarshaller here to handle the position information for searches
	if node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return fmt.Errorf("cannot unmarshal %d into Detection", node.Kind)
	}

	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]

		switch key.Value {
		case "condition":
			if err := d.Conditions.UnmarshalYAML(value); err != nil {
				return err
			}
		case "timeframe":
			// Extract the timeframe value as a string
			timeframeStr := value.Value
			// Clean up the whitespace (if any) from the string
			timeframeStr = strings.TrimSpace(timeframeStr)

			// Parse the duration
			duration, err := time.ParseDuration(timeframeStr)
			if err != nil {
				return err
			}
			// Assign the parsed duration to the Timeframe field
			d.Timeframe = duration

		default:
			search := Search{}
			if err := search.UnmarshalYAML(value); err != nil {
				return err
			}
			search.node = key
			if d.Searches == nil {
				d.Searches = map[string]Search{}
			}
			d.Searches[key.Value] = search
		}

	}
	return nil
}

type Conditions []Condition

// UnmarshalYAML unmarshals the YAML node to the Conditions slice.
func (c *Conditions) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var condition string
		if err := node.Decode(&condition); err != nil {
			return err
		}

		parsed, err := ParseCondition(condition) // Parse the condition string into a Condition struct.
		if err != nil {
			return err
		}
		parsed.node = node
		*c = []Condition{parsed}

	case yaml.SequenceNode:
		var conditions []string
		if err := node.Decode(&conditions); err != nil {
			return err
		}
		for i, condition := range conditions {
			parsed, err := ParseCondition(condition) // Parse each condition string in the slice into a Condition struct.
			if err != nil {
				return fmt.Errorf("error parsing condition \"%s\": %w", condition, err)
			}
			parsed.node = node.Content[i]
			*c = append(*c, parsed) // Append the parsed Condition struct to the Conditions slice.
		}

	default:
		return fmt.Errorf("invalid condition (line %d). Expected a single value or a list", node.Line)
	}

	return nil
}

// MarshalYAML marshals the Conditions slice to YAML.
func (c Conditions) MarshalYAML() (interface{}, error) {
	if len(c) == 1 {
		return c[0], nil // If there is only one Condition in the slice, return it.
	} else {
		return []Condition(c), nil // Otherwise, return the Conditions slice as a sequence of Condition structs.
	}
}

// Search defines a search criteria that can be used to match events.
type Search struct {
	node          *yaml.Node     `yaml:",omitempty" json:",omitempty"`
	Keywords      []string       `yaml:",omitempty" json:",omitempty"` // Keywords to search for
	EventMatchers []EventMatcher `yaml:",omitempty" json:",omitempty"` // List of event matchers (maps of fields to values)
}

// Position returns the line and column of this Search in the original input
func (s Search) Position() (int, int) {
	return s.node.Line - 1, s.node.Column - 1
}

// UnmarshalYAML decodes the YAML representation of a Search object.
func (s *Search) UnmarshalYAML(node *yaml.Node) error {
	s.node = node
	switch node.Kind {
	// In the common case, SearchIdentifiers are a single EventMatcher (map of field names to values)
	case yaml.MappingNode:
		// Allocate a single element slice for EventMatchers
		s.EventMatchers = []EventMatcher{{}}
		// Decode the mapping node into the single element slice
		return node.Decode(&s.EventMatchers[0])

	// Or, SearchIdentifiers can be a list.
	// Either of keywords (not supported by this library) or a list of EventMatchers (maps of fields to values)
	case yaml.SequenceNode:
		if len(node.Content) == 0 {
			return fmt.Errorf("invalid search condition node (empty) (line %d)", node.Line)
		}

		switch node.Content[0].Kind {
		case yaml.ScalarNode:
			// If the first item is a scalar, then it is a list of keywords.
			return node.Decode(&s.Keywords)
		case yaml.MappingNode:
			// If the first item is a mapping, then it is a list of EventMatchers.
			return node.Decode(&s.EventMatchers)
		default:
			return fmt.Errorf("invalid list (line %d). Expected a list of strings or a list of maps", node.Line)
		}

	default:
		return fmt.Errorf("invalid search (line %d). Expected a map or list, got a scalar", node.Line)
	}
}

// MarshalYAML encodes the Search object into a YAML representation.
func (s Search) MarshalYAML() (interface{}, error) {
	var err error
	result := &yaml.Node{}

	if s.Keywords != nil {
		// Encode a list of keywords
		err = result.Encode(&s.Keywords)
	} else if len(s.EventMatchers) == 1 {
		// Encode a single EventMatcher
		err = result.Encode(&s.EventMatchers[0])
	} else if len(s.EventMatchers) == 0 {
		// If there are no search criteria
		err = fmt.Errorf("no search criteria")
	} else {
		// Encode a list of EventMatchers
		err = result.Encode(&s.EventMatchers)
	}

	return result, err
}

type EventMatcher []FieldMatcher

// UnmarshalYAML parses the YAML node and sets the fields on the EventMatcher struct
func (f *EventMatcher) UnmarshalYAML(node *yaml.Node) error {
	// EventMatchers are represented as key-value pairs in YAML, so we expect the node
	// to be a mapping node with an even number of content elements
	if len(node.Content)%2 != 0 {
		return fmt.Errorf("internal: node.Content %% 2 != 0")
	}

	// Loop through each content element, parsing the field and value pairs into
	// FieldMatcher structs and appending them to the EventMatcher slice
	for i := 0; i < len(node.Content); i += 2 {
		matcher := FieldMatcher{}
		err := matcher.unmarshal(node.Content[i], node.Content[i+1])
		if err != nil {
			return err
		}
		*f = append(*f, matcher)
	}
	return nil
}

// MarshalYAML returns a YAML representation of the EventMatcher struct
func (f EventMatcher) MarshalYAML() (interface{}, error) {

	// EventMatchers are represented as key-value pairs in YAML, so we create a
	// new mapping node to hold the field-value pairs
	result := &yaml.Node{
		Kind: yaml.MappingNode,
	}

	// Loop through each FieldMatcher in the slice, marshaling them into key-value pairs
	for _, matcher := range f {
		// Reconstruct the field and value nodes using the FieldMatcher's marshal method
		if field_node, value_node, err := matcher.marshal(); err != nil {
			return nil, err
		} else {
			// Append the field and value nodes to the content of the mapping node
			result.Content = append(result.Content, field_node, value_node)
		}
	}

	return result, nil
}

// FieldMatcher defines a matcher for a single field
type FieldMatcher struct {
	node      *yaml.Node    `yaml:",omitempty" json:",omitempty"`
	Field     string        `yaml:",omitempty" json:",omitempty"`
	Modifiers []string      `yaml:",omitempty" json:",omitempty"`
	Values    []interface{} `yaml:",omitempty" json:",omitempty"`
}

// Position returns the line and column of this FieldMatcher in the original input
func (f FieldMatcher) Position() (int, int) {
	return f.node.Line - 1, f.node.Column - 1
}

// unmarshal decodes a single FieldMatcher
func (f *FieldMatcher) unmarshal(field *yaml.Node, values *yaml.Node) error {
	// Split the field name and modifiers
	f.node = field
	fieldParts := strings.Split(field.Value, "|")
	f.Field, f.Modifiers = fieldParts[0], fieldParts[1:]

	// Decode the field value(s)
	switch values.Kind {
	case yaml.ScalarNode:
		// If there is only one value, decode it into the first element of the Values slice
		f.Values = []interface{}{nil}
		return values.Decode(&f.Values[0])
	case yaml.SequenceNode:
		// If there are multiple values, decode them into the Values slice
		return values.Decode(&f.Values)
	case yaml.MappingNode:
		// If there is a nested mapping, decode it into the first element of the Values slice
		f.Values = []interface{}{map[string]interface{}{}}
		return values.Decode(&f.Values[0])
	case yaml.AliasNode:
		// If the values are an alias, recursively decode the target
		return f.unmarshal(field, values.Alias)
	}
	return nil
}

// marshal encodes a single FieldMatcher
func (f *FieldMatcher) marshal() (field_node *yaml.Node, value_node *yaml.Node, err error) {
	// Encode the field name with modifiers
	field := f.Field
	if len(f.Modifiers) > 0 {
		field = field + "|" + strings.Join(f.Modifiers, "|")
	}

	// Encode the field name
	field_node = &yaml.Node{}
	err = field_node.Encode(&field)
	if err != nil {
		return nil, nil, err
	}

	// Encode the field value(s)
	value_node = &yaml.Node{}
	if len(f.Values) == 1 {
		// If there is only one value, encode it as a scalar
		err = value_node.Encode(&f.Values[0])
	} else {
		// If there are multiple values, encode them as a sequence
		err = value_node.Encode(&f.Values)
	}
	if err != nil {
		return nil, nil, err
	}

	return field_node, value_node, err
}

// ParseRule reads a byte slice and returns a parsed Rule object and an error (if any)
func ParseRule(input []byte) (Rule, error) {
	// Create a Rule instance to hold the parsed YAML data
	rule := Rule{}

	// Unmarshal the input YAML data into the Rule instance
	err := yaml.Unmarshal(input, &rule)

	// Return the Rule instance and error (if any)
	return rule, err
}
