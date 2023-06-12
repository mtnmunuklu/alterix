package sigma

import (
	"testing"
)

// Test_isSigmaRule tests the functionality of the InferFileType function, which is used to determine the type of a Sigma file based on its contents. The test inputs include example Sigma rule and config files, as well as an invalid file. The expected output is the inferred file type for each input.

func Test_isSigmaRule(t *testing.T) {
	tests := []struct {
		file         string   // A string representing the file content to be tested
		expectedType FileType // The expected FileType that should be inferred from the file
	}{
		{
			// An example configuration file content
			`title: foo
logsources:
  foo:
    category: process_creation
    index: bar
`,
			ConfigFile, // The expected type is ConfigFile
		},
		{
			// An example rule file content
			`title: foo
detection:
    foo:
        - bar
        - baz
    selection: foo
`,
			RuleFile, // The expected type is RuleFile
		},
		{
			// An example invalid file content
			`this: |
isnt valid`,
			InvalidFile, // The expected type is InvalidFile
		},
	}

	for _, tt := range tests {
		// Infer the file type from the byte slice of the file content
		fileType := InferFileType([]byte(tt.file))
		if fileType != tt.expectedType {
			// If the inferred file type does not match the expected type, fail the test and print the error message
			t.Errorf("Expected\n%s\not be detected as a %s", tt.file, tt.expectedType)
		}
	}
}
