package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/mtnmunuklu/alterix/sigma"
	"github.com/mtnmunuklu/alterix/sigma/evaluator"
)

var (
	filePath   string
	configPath string
	showHelp   bool
)

// Set up the command-line flags
func init() {
	flag.StringVar(&filePath, "filepath", "", "Name or path of the file or directory to read")
	flag.StringVar(&configPath, "config", "", "Path to the configuration file")
	flag.BoolVar(&showHelp, "help", false, "Show usage")
	flag.Parse()
}

func main() {
	// If the help flag is provided, print usage information and exit
	if showHelp {
		flag.Usage()
		return
	}

	// Check that the filepath flag is provided
	if filePath == "" {
		fmt.Println("Please provide a file path or directory path with the -filepath flag.")
		return
	}

	// Check that the config flag is provided
	if configPath == "" {
		fmt.Println("Please provide a configuration file path with the -config flag.")
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
		fmt.Println("Filepath:", file)
		rule, err := sigma.ParseRule(fileContent)
		if err != nil {
			fmt.Println("Error parsing rule:", err)
			return
		}

		// Parse the configuration file as a Sigma config
		config, err := sigma.ParseConfig(configContent)
		if err != nil {
			fmt.Println("Error parsing config:", err)
			return
		}

		// Evaluate the Sigma rule against the config
		r := evaluator.ForRule(rule, evaluator.WithConfig(config))
		ctx := context.Background()
		result, err := r.Alters(ctx)
		if err != nil {
			fmt.Println("Error converting rule:", err)
			return
		}

		// Print the results of the query
		for _, queryResult := range result.QueryResults {
			fmt.Printf("Query: %v\n", queryResult)
		}
	}
}
