package sigma

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
)

// TestParseConfig walks through the data directory and looks for all files with a .config.yml extension.
// For each file found, it runs a subtest and attempts to parse the file as a Config object.
// If successful, it generates a snapshot using cupaloy to ensure that the parsed object matches the expected output.
func TestParseConfig(t *testing.T) {
	// Walk through the "data/" directory and its subdirectories recursively.
	// For each ".config.yml" file found, run a test with the file's contents.
	err := filepath.Walk("./data/configs/", func(path string, info os.FileInfo, err error) error {
		fmt.Println("path", path)
		if !strings.HasSuffix(path, ".config.yml") {
			return nil
		}

		t.Run(strings.TrimSuffix(filepath.Base(path), ".config.yml"), func(t *testing.T) {
			// Read the contents of the config file.
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed reading test input: %v", err)
			}

			// Parse the config file.
			rule, err := ParseConfig(contents)
			if err != nil {
				t.Fatalf("error parsing config: %v", err)
			}

			// Use Cupaloy to compare the parsed rule to a snapshot of the expected output.
			cupaloy.New(cupaloy.SnapshotSubdirectory("data")).SnapshotT(t, rule)
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
