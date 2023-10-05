package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	path           string // Path to the JSON file or directory containing JSON files.
	output         string // Path to save the output file.
	forbiddenWords string // Forbidden words.
)

func init() {
	flag.StringVar(&path, "path", "", "Path to the JSON file or directory containing JSON files")
	flag.StringVar(&output, "output", "", "Path to save the output file")
	flag.StringVar(&forbiddenWords, "words", "", "Comma-separated list of forbidden words.")
	flag.Parse()
}

type Data struct {
	Name  string `json:"Name"`
	Query string `json:"Query"`
}

// findForbiddenWords finds forbidden words in a query and returns them in a list.
func findForbiddenWords(query, forbiddenWords string) []string {
	// Split the forbiddenWords string by commas to get individual forbidden names
	forbiddenNames := strings.Split(forbiddenWords, ",")
	for i, name := range forbiddenNames {
		forbiddenNames[i] = strings.TrimSpace(name)
	}

	// Find forbidden words in the query
	forbiddens := []string{}

	for _, name := range forbiddenNames {
		if strings.Contains(query, name) {
			forbiddens = append(forbiddens, name)
		}
	}

	return forbiddens
}

func processJSONData(data Data, forbiddens *[]struct {
	QueryName      string
	Query          string
	ForbiddenWords []string
}, forbiddenColumnNames string) {

	forbiddenWords := findForbiddenWords(data.Query, forbiddenWords)
	if len(forbiddenWords) > 0 {
		*forbiddens = append(*forbiddens, struct {
			QueryName      string
			Query          string
			ForbiddenWords []string
		}{
			QueryName:      data.Name,
			Query:          data.Query,
			ForbiddenWords: forbiddenWords,
		})
	}
}

func processJSONArray(jsonArray []Data, forbiddens *[]struct {
	QueryName      string
	Query          string
	ForbiddenWords []string
}, forbiddenWords string) {
	for _, data := range jsonArray {
		processJSONData(data, forbiddens, forbiddenWords)
	}
}

func processJSONFile(filePath string, forbiddens *[]struct {
	QueryName      string
	Query          string
	ForbiddenWords []string
}, forbiddenWords string) error {
	// Open the JSON file for reading
	jsonFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer jsonFile.Close()

	var jsonData interface{} // A generic intermediate type for JSON data

	// Create a JSON decoder and decode the JSON data
	decoder := json.NewDecoder(jsonFile)
	if err := decoder.Decode(&jsonData); err != nil {
		fmt.Println("Error decoding JSON file:", err)
		return err
	}

	// Determine the type of JSON data and process accordingly
	switch jsonData := jsonData.(type) {
	case []interface{}:
		// JSON array has arrived
		jsonArray := make([]Data, len(jsonData))
		for i, item := range jsonData {
			if dataMap, ok := item.(map[string]interface{}); ok {
				// Convert the data to JSON
				if jsonDataBytes, err := json.Marshal(dataMap); err == nil {
					if err := json.Unmarshal(jsonDataBytes, &jsonArray[i]); err != nil {
						fmt.Println("Error decoding JSON data:", err)
					}
				} else {
					fmt.Println("Error encoding JSON data:", err)
				}
			}
		}
		// You can use jsonArray here
		processJSONArray(jsonArray, forbiddens, forbiddenWords)
	case map[string]interface{}:
		// JSON object has arrived
		jsonDataBytes, err := json.Marshal(jsonData)
		if err != nil {
			fmt.Println("Error encoding JSON data:", err)
			return err
		}
		var data Data
		if err := json.Unmarshal(jsonDataBytes, &data); err != nil {
			fmt.Println("Error decoding JSON data:", err)
			return err
		}
		// You can use data here
		processJSONArray([]Data{data}, forbiddens, forbiddenWords)
	default:
		fmt.Println("Unexpected JSON data format")
	}

	return nil
}

func writeForbiddensToFile(filename string, forbiddens interface{}) error {
	outputFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Create a JSON encoder for writing data to the output file
	encoder := json.NewEncoder(outputFile)

	// Iterate through the list of forbidden records and encode each one
	for _, forbidden := range forbiddens.([]struct {
		QueryName      string
		Query          string
		ForbiddenWords []string
	}) {
		if err := encoder.Encode(forbidden); err != nil {
			return err
		}
	}

	return nil
}

func main() {

	if path == "" || output == "" || forbiddenWords == "" {
		fmt.Println("Usage: go run main.go -path <jsonFilePath> -output <output> -words <forbiddenWords>")
		flag.PrintDefaults()
		return
	}

	stat, err := os.Stat(path)
	if err != nil {
		fmt.Println("Error opening JSON file or directory:", err)
		return
	}

	forbiddens := []struct {
		QueryName      string
		Query          string
		ForbiddenWords []string
	}{}

	if stat.IsDir() {
		err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(info.Name(), ".json") {
				if err := processJSONFile(path, &forbiddens, forbiddenWords); err != nil {
					fmt.Println("Error processing JSON file:", err)
				}
			}
			return nil
		})
		if err != nil {
			fmt.Println("Error reading JSON files:", err)
		}
	} else {
		if err := processJSONFile(path, &forbiddens, forbiddenWords); err != nil {
			fmt.Println("Error processing JSON file:", err)
			return
		}
	}

	// Write forbiddens to the output file
	if err := writeForbiddensToFile(output, forbiddens); err != nil {
		fmt.Println("Error writing forbiddens to output file:", err)
	}
}
