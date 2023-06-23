package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mtnmunuklu/alterix/sigma"
	"github.com/mtnmunuklu/alterix/sigma/evaluator"
)

var (
	filePath   string
	configPath string
	showHelp   bool
	outputJSON bool
	outputPath string
	version    bool
)

// Set up the command-line flags
func init() {
	flag.StringVar(&filePath, "filepath", "", "Name or path of the file or directory to read")
	flag.StringVar(&configPath, "config", "", "Path to the configuration file")
	flag.BoolVar(&showHelp, "help", false, "Show usage")
	flag.BoolVar(&outputJSON, "json", false, "Output results in JSON format")
	flag.StringVar(&outputPath, "output", "", "Output directory for writing files")
	flag.BoolVar(&version, "version", false, "Show version information")
	flag.Parse()
}

func formatJSONResult(rule sigma.Rule, result map[int]string) []byte {
	// Define a struct type named JSONResult to represent the JSON output fields.
	type JSONResult struct {
		Name           string   `json:"Name"`
		Description    string   `json:"Description"`
		Query          string   `json:"Query"`
		InsertDate     string   `json:"InsertDate"`
		LastUpdateDate string   `json:"LastUpdateDate"`
		Tags           []string `json:"Tags"`
	}

	// Create a strings.Builder variable named query.
	var query strings.Builder
	for i, value := range result {
		// Add a newline character if the index is greater than zero.
		if i > 0 {
			query.WriteString("\n")
		}
		query.WriteString(value)
	}

	// Create an instance of the JSONResult struct.
	jsonResult := JSONResult{
		Name:           rule.Title,
		Description:    rule.Description,
		Query:          query.String(),
		InsertDate:     time.Now().UTC().Format(time.RFC3339),
		LastUpdateDate: time.Now().UTC().Format(time.RFC3339),
		Tags:           rule.Tags,
	}

	// Marshal the JSONResult struct into JSON data.
	jsonData, err := json.MarshalIndent(jsonResult, "", "  ")
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
		return nil
	}

	return jsonData
}

func printUsage() {
	fmt.Println("Usage: alterix -filepath <path> -config <path> [flags]")
	fmt.Println("Flags:")
	flag.PrintDefaults()
	fmt.Println("Example:")
	fmt.Println("  alterix -filepath /path/to/file -config /path/to/config")
}

func main() {
	// If the help flag is provided, print usage information and exit
	if showHelp {
		printUsage()
		return
	}

	// If the version flag is provided, print version information and exit
	if version {
		fmt.Println("Alterix version 1.0.0")
		return
	}

	// Check that the filepath flag is provided
	if filePath == "" {
		fmt.Println("Please provide a file path or directory path with the -filepath flag.")
		printUsage()
		return
	}

	// Check that the config flag is provided
	if configPath == "" {
		fmt.Println("Please provide a configuration file path with the -config flag.")
		printUsage()
		return
	}

	// Read the contents of the file(s) specified by the filepath flag
	fileContents := make(map[string][]byte)
	var err error

	// Check if the filepath is a directory
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		fmt.Println("Error getting file/directory info:", err)
		return
	}

	if fileInfo.IsDir() {
		// filePath is a directory, so walk the directory to read all the files inside it
		filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Println("Error accessing file:", err)
				return nil
			}
			if !info.IsDir() {
				// read file content
				content, err := ioutil.ReadFile(path)
				if err != nil {
					fmt.Println("Error reading file:", err)
					return nil
				}
				fileContents[path] = content
			}
			return nil
		})
	} else {
		// filePath is a file, so read its contents
		fileContents[filePath], err = ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
	}

	// Read the contents of the configuration file
	configContent, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Println("Error reading configuration file:", err)
		return
	}

	// Loop over each file and parse its contents as a Sigma rule
	for file, fileContent := range fileContents {
		rule, err := sigma.ParseRule(fileContent)
		if err != nil {
			fmt.Println("Error parsing rule:", err)
			continue
		}

		// Parse the configuration file as a Sigma config
		config, err := sigma.ParseConfig(configContent)
		if err != nil {
			fmt.Println("Error parsing config:", err)
			continue
		}

		// Evaluate the Sigma rule against the config
		r := evaluator.ForRule(rule, evaluator.WithConfig(config))
		ctx := context.Background()
		result, err := r.Alters(ctx)
		if err != nil {
			fmt.Println("Error converting rule:", err)
			continue
		}

		var output string

		// Print the results of the query
		if outputJSON {
			jsonResult := formatJSONResult(rule, result.QueryResults)
			output = string(jsonResult)
		} else {
			var builder strings.Builder
			builder.WriteString("Filepath: " + file + "\n")
			for _, queryResult := range result.QueryResults {
				builder.WriteString("Query: " + queryResult + "\n")
			}
			output = builder.String()
		}

		// Check if outputPath is provided
		if outputPath != "" {
			// Create the output file path using the Name field from the rule
			outputFilePath := filepath.Join(outputPath, fmt.Sprintf("%s.json", rule.Title))

			// Write the output string to the output file
			err := os.WriteFile(outputFilePath, []byte(output), 0644)
			if err != nil {
				fmt.Println("Error writing output to file:", err)
				continue
			}

			fmt.Printf("Output for rule '%s' written to file: %s\n", rule.Title, outputFilePath)
		} else {
			fmt.Printf("%s", output)
		}
	}
}
