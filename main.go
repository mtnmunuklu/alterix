package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mtnmunuklu/alterix/sigma"
	"github.com/mtnmunuklu/alterix/sigma/sevaluator"
	"github.com/mtnmunuklu/alterix/yara"
	"github.com/mtnmunuklu/alterix/yara/yevaluator"
)

var (
	filePath      string
	configPath    string
	fileContent   string
	configContent string
	showHelp      bool
	outputJSON    bool
	outputPath    string
	version       bool
	caseSensitive bool
	useSigma      bool
	useYara       bool
)

// Set up the command-line flags
func init() {
	flag.StringVar(&filePath, "filepath", "", "Name or path of the file or directory to read")
	flag.StringVar(&configPath, "config", "", "Path to the configuration file")
	flag.StringVar(&fileContent, "filecontent", "", "Base64-encoded content of the file or directory to read")
	flag.StringVar(&configContent, "configcontent", "", "Base64-encoded content of the configuration file")
	flag.BoolVar(&showHelp, "help", false, "Show usage")
	flag.BoolVar(&outputJSON, "json", false, "Output results in JSON format")
	flag.StringVar(&outputPath, "output", "", "Output directory for writing files")
	flag.BoolVar(&version, "version", false, "Show version information")
	flag.BoolVar(&caseSensitive, "cs", false, "Case sensitive mode")
	flag.BoolVar(&useSigma, "sigma", false, "Use Sigma rules")
	flag.BoolVar(&useYara, "yara", false, "Use Yara rules")
	flag.Parse()

	// If the version flag is provided, print version information and exit
	if version {
		fmt.Println("Alterix version 1.4.0")
		os.Exit(1)
	}

	// If the help flag is provided, print usage information and exit
	if showHelp {
		printUsage()
		os.Exit(1)
	}

	// Check if filepath and configpath are provided as command-line arguments
	if flag.NArg() > 0 {
		filePath = flag.Arg(0)
	}
	if flag.NArg() > 1 {
		configPath = flag.Arg(1)
	}

	// Check if both filecontent and configcontent are provided
	if (filePath == "" && fileContent == "") || (configPath == "" && configContent == "") {
		fmt.Println("Please provide either file paths or file contents, and either config path or config content.")
		printUsage()
		os.Exit(1)
	}
}

func formatSigmaJSONResult(rule sigma.Rule, queries map[int]string) []byte {
	// Define a struct type named JSONResult to represent the JSON output fields.
	type JSONResult struct {
		Name           string   `json:"Name"`
		Description    string   `json:"Description"`
		Query          string   `json:"Query"`
		InsertDate     string   `json:"InsertDate"`
		LastUpdateDate string   `json:"LastUpdateDate"`
		Tags           []string `json:"Tags"`
		Level          string   `json:"Level"`
	}

	// Create a strings.Builder variable named query.
	var query strings.Builder
	for i, qry := range queries {
		// Add a newline character if the index is greater than zero.
		if i > 0 {
			query.WriteString("\n")
		}
		query.WriteString(qry)
	}

	// Create an instance of the JSONResult struct.
	jsonResult := JSONResult{
		Name:           rule.Title,
		Description:    rule.Description + "\n\nAuthor: " + rule.Author + "\nSigma Repository: [GitHub](https://github.com/SigmaHQ/sigma)",
		Query:          query.String(),
		InsertDate:     time.Now().UTC().Format(time.RFC3339),
		LastUpdateDate: time.Now().UTC().Format(time.RFC3339),
		Tags:           rule.Tags,
		Level:          rule.Level,
	}

	// Marshal the JSONResult struct into JSON data.
	jsonData, err := json.MarshalIndent(jsonResult, "", "  ")
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
		return nil
	}

	return jsonData
}

func formatYaraJSONResult(title, query string, tags []string, metas map[string]string) []byte {
	// Define a struct type named JSONResult to represent the JSON output fields.
	type JSONResult struct {
		Name           string   `json:"Name"`
		Description    string   `json:"Description"`
		Query          string   `json:"Query"`
		InsertDate     string   `json:"InsertDate"`
		LastUpdateDate string   `json:"LastUpdateDate"`
		Tags           []string `json:"Tags"`
		Level          string   `json:"Level"`
	}

	// Convert the keys in metas map to lowercase
	lowercaseMetas := make(map[string]string)
	for key, value := range metas {
		lowercaseMetas[strings.ToLower(key)] = value
	}

	// Check if the "description" and "author" fields are present in the lowercaseMetas map
	var description, author string
	if val, ok := lowercaseMetas["description"]; ok {
		description = val
	}
	if val, ok := lowercaseMetas["author"]; ok {
		author = val
	}

	// Create an instance of the JSONResult struct.
	jsonResult := JSONResult{
		Name:           title,
		Description:    description + "\n\nAuthor: " + author,
		Query:          query,
		InsertDate:     time.Now().UTC().Format(time.RFC3339),
		LastUpdateDate: time.Now().UTC().Format(time.RFC3339),
		Tags:           tags,
		Level:          "",
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
	fmt.Println("Usage: alterix -sigma/-yara -filepath <path> -config <path> [flags]")
	fmt.Println("Flags:")
	flag.PrintDefaults()
	fmt.Println("Example:")
	fmt.Println("  alterix -sigma/-yara -filepath /path/to/file -config /path/to/config")
}

func main() {
	// Ensure either Sigma or Yara flag is provided
	if !useSigma && !useYara {
		fmt.Println("Please provide either --sigma or --yara flag to specify the type of rules.")
		printUsage()
		os.Exit(1)
	}

	// Read the contents of the file(s) specified by the filepath flag or filecontent flag
	fileContents := make(map[string][]byte)
	var err error

	// Check if file paths are provided
	if filePath != "" {
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
					content, err := os.ReadFile(path)
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
			fileContents[filePath], err = os.ReadFile(filePath)
			if err != nil {
				fmt.Println("Error reading file:", err)
				return
			}
		}
	} else if fileContent != "" {
		// Check if the filecontent is a directory
		lines := strings.Split(fileContent, "\n")
		if len(lines) > 1 {
			// fileContent is a directory, so read all lines as separate files
			for _, line := range lines {
				// decode base64 content
				decodedContent, err := base64.StdEncoding.DecodeString(line)
				if err != nil {
					fmt.Println("Error decoding base64 content:", err)
					return
				}
				fileContents[line] = decodedContent
			}
		} else {
			// fileContent is a file, so read its content
			// decode base64 content
			decodedContent, err := base64.StdEncoding.DecodeString(fileContent)
			if err != nil {
				fmt.Println("Error decoding base64 content:", err)
				return
			}
			fileContents["filecontent"] = decodedContent
		}
	}

	// Read the contents of the configuration file or use configcontent
	var configContents []byte
	if configPath != "" {
		configContents, err = os.ReadFile(configPath)
		if err != nil {
			fmt.Println("Error reading configuration file:", err)
			return
		}
	} else if configContent != "" {
		// decode base64 content
		decodedContent, err := base64.StdEncoding.DecodeString(configContent)
		if err != nil {
			fmt.Println("Error decoding base64 content:", err)
			return
		}
		configContents = decodedContent
	}

	// Loop over each file and parse its contents as a Sigma rule
	for _, fileContent := range fileContents {
		if useSigma {
			sigmaRule, err := sigma.ParseRule(fileContent)
			if err != nil {
				fmt.Println("Error parsing rule:", err)
				continue
			}

			// Parse the configuration file as a Sigma config
			config, err := sigma.ParseConfig(configContents)
			if err != nil {
				fmt.Println("Error parsing config:", err)
				continue
			}

			var sr *sevaluator.RuleEvaluator

			if caseSensitive {
				// Evaluate the Sigma rule against the config using case sensitive mode
				sr = sevaluator.ForRule(sigmaRule, sevaluator.WithConfig(config), sevaluator.CaseSensitive)
			} else {
				// Evaluate the Sigma rule against the config
				sr = sevaluator.ForRule(sigmaRule, sevaluator.WithConfig(config))
			}

			ctx := context.Background()
			result, err := sr.Alters(ctx)
			if err != nil {
				fmt.Println("Error converting rule:", err)
				continue
			}

			var output string

			// Print the results of the query
			if outputJSON {
				jsonResult := formatSigmaJSONResult(sigmaRule, result.QueryResults)
				output = string(jsonResult)
			} else {
				var builder strings.Builder
				for _, queryResult := range result.QueryResults {
					builder.WriteString(queryResult + "\n")
				}
				output = builder.String()
			}

			// Check if outputPath is provided
			if outputPath != "" {
				// Create the output file path using the Name field from the rule
				outputFilePath := filepath.Join(outputPath, fmt.Sprintf("%s.json", sigmaRule.Title))

				// Write the output string to the output file
				err := os.WriteFile(outputFilePath, []byte(output), 0644)
				if err != nil {
					fmt.Println("Error writing output to file:", err)
					continue
				}

				fmt.Printf("Output for rule '%s' written to file: %s\n", sigmaRule.Title, outputFilePath)
			} else {
				fmt.Printf("%s", output)
			}
		} else if useYara {
			yaraRuleSet, err := yara.ParseByte(fileContent)
			if err != nil {
				fmt.Println("Error parsing rule:", err)
				continue
			}

			// Parse the configuration file as a Yara config
			config, err := yara.ParseConfig(configContents)
			if err != nil {
				fmt.Println("Error parsing config:", err)
				continue
			}

			for _, yaraRule := range yaraRuleSet.Rules {
				// Evaluate the Yara rule against the config
				yr := yevaluator.ForRule(yaraRule, yevaluator.WithConfig(config))
				result, err := yr.Alters()
				if err != nil {
					fmt.Println("Error converting rule:", err)
					continue
				}

				var output string

				// Print the results of the query
				if outputJSON {
					jsonResult := formatYaraJSONResult(yaraRule.Identifier, result.QueryResult, yaraRule.Tags, result.MetaResults)
					output = string(jsonResult)
				} else {
					output = result.QueryResult
				}

				// Check if outputPath is provided
				if outputPath != "" {
					// Create the output file path using the Name field from the rule
					outputFilePath := filepath.Join(outputPath, fmt.Sprintf("%s.json", yaraRule.Identifier))

					// Write the output string to the output file
					err := os.WriteFile(outputFilePath, []byte(output), 0644)
					if err != nil {
						fmt.Println("Error writing output to file:", err)
						continue
					}

					fmt.Printf("Output for rule '%s' written to file: %s\n", yaraRule.Identifier, outputFilePath)
				} else {
					fmt.Printf("%s", output)
				}
			}
		}
	}
}
