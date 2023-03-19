package sigma

import (
	"gopkg.in/yaml.v3"
)

// InferFileType attempts to infer the type of Sigma file by unmarshalling the YAML contents
// and checking if it contains certain required fields for a rule or config file.
// If there is an error unmarshalling the contents, it returns an invalid file type.
func InferFileType(contents []byte) FileType {
	var fileType FileType
	if err := yaml.Unmarshal(contents, &fileType); err != nil {
		fileType = InvalidFile // If there is an error unmarshalling, assume the file is invalid
	}
	return fileType
}

// FileType represents the type of a Sigma file
type FileType string

// Possible file types
const (
	UnknownFile FileType = ""        // Unknown file type
	InvalidFile FileType = "invalid" // Invalid file type
	RuleFile    FileType = "rule"    // Sigma rule file type
	ConfigFile  FileType = "config"  // Sigma config file type
)

// UnmarshalYAML is a custom unmarshaller for the FileType type.
// It checks if the YAML node contains certain required fields for a rule or config file,
// and sets the corresponding FileType value.
func (f *FileType) UnmarshalYAML(node *yaml.Node) error {
	// Check if there's a key called "detection".
	// This is a required field in a Sigma rule but doesn't exist in a config
	for _, node := range node.Content {
		if node.Kind == yaml.ScalarNode && node.Value == "detection" {
			*f = RuleFile // If the node contains the "detection" key, assume it's a rule file
			return nil
		}
		if node.Kind == yaml.ScalarNode && node.Value == "logsources" {
			*f = ConfigFile // If the node contains the "logsources" key, assume it's a config file
			return nil
		}
	}
	return nil
}
