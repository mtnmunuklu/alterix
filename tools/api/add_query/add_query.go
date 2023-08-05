package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type QuerySettings struct {
	Name        string   `json:"Name"`
	Description string   `json:"Description"`
	Tags        []string `json:"Tags"`
	Query       string   `json:"Query"`
	Author      string   `json:"Author"`
	Level       string   `json:"Level"`
}

type SavePayload struct {
	QuerySettings           QuerySettings `json:"querySettings"`
	SmartRestRequestContext string        `json:"smartRestRequestContext"`
}

type GetPayload struct {
	Username                string `json:"username"`
	Filter                  string `json:"filter"`
	SmartRestRequestContext string `json:"smartRestRequestContext"`
}

var (
	xAPIKey           string
	jsonFilePath      string
	urlHostname       string
	responseDirectory string
	author            string
)

func init() {
	flag.StringVar(&xAPIKey, "x-api-key", "", "API key for authentication")
	flag.StringVar(&jsonFilePath, "json-file-path", "", "Path to the JSON file or directory containing JSON files")
	flag.StringVar(&urlHostname, "url-hostname", "", "Hostname of the URL")
	flag.StringVar(&responseDirectory, "response-file-dir", "", "Directory to save response files")
	flag.StringVar(&author, "author", "", "Author to update in the payload")
	flag.Parse()
}

func SaveRequest(xAPIKey, saveFullURL, method, responseDirectory string, savePayload SavePayload) error {

	savePayloadBytes, err := json.Marshal(savePayload)
	if err != nil {
		return fmt.Errorf("error marshaling JSON payload: %w", err)
	}

	req, err := http.NewRequest(method, saveFullURL, strings.NewReader(string(savePayloadBytes)))
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}

	req.Header.Add("x-api-key", xAPIKey)
	req.Header.Add("Content-Type", "application/json")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	// Send HTTP request and get the response
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("error reading HTTP response: %w", err)
	}

	// Decode the JSON response
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return fmt.Errorf("error decoding JSON response: %w", err)
	}

	status, ok := jsonResponse["status"].(bool)
	if !ok {
		return fmt.Errorf("invalid JSON response: missing or invalid 'status' field")
	}

	if !status {
		return fmt.Errorf("request failed: status is not true")
	}

	// Predefined mapping for severity levels
	levelMapping := map[string]int{
		"critical": 10,
		"high":     8,
		"medium":   7,
		"Low":      6,
		"info":     5,
	}

	// Get the value for savePayload.QuerySettings.Level
	levelValue, exists := levelMapping[savePayload.QuerySettings.Level]
	if !exists {
		fmt.Printf("Level is invalid. Info level is used: %s", savePayload.QuerySettings.Level)
		levelValue = 5
	}

	// Add the Level field to the final response data
	jsonResponse["query"].(map[string]interface{})["RiskLevel"] = levelValue

	// Create a filename using the value of the "Name" field
	filename := fmt.Sprintf("%s.json", savePayload.QuerySettings.Name)

	// Write the JSON response to a file
	responseFilePath := filepath.Join(responseDirectory, filename)
	err = writeJSONToFile(responseFilePath, jsonResponse)
	if err != nil {
		return fmt.Errorf("error writing JSON response to file: %w", err)
	}

	fmt.Printf("Response received and saved to %s\n", responseFilePath)
	return nil
}

func GetRequest(xAPIKey, getFullURL, method string, getPayload GetPayload) error {

	getPayloadBytes, err := json.Marshal(getPayload)
	if err != nil {
		return fmt.Errorf("error marshaling JSON payload: %w", err)
	}

	req, err := http.NewRequest(method, getFullURL, strings.NewReader(string(getPayloadBytes)))
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}

	req.Header.Add("x-api-key", xAPIKey)
	req.Header.Add("Content-Type", "application/json")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	// Send HTTP request and get the response
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("error reading HTTP response: %w", err)
	}

	// Decode the JSON response
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return fmt.Errorf("error decoding JSON response: %w", err)
	}

	if items, ok := jsonResponse["Items"].([]interface{}); ok {
		itemsCount := len(items)
		if itemsCount > 0 {
			return fmt.Errorf("rule is already exist: %s", getPayload.Filter)
		}
	}

	return nil
}

func writeJSONToFile(filename string, data map[string]interface{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Set indentation to 1 spaces
	if err := encoder.Encode(data); err != nil {
		return err
	}

	return nil
}

func main() {

	if xAPIKey == "" || jsonFilePath == "" || urlHostname == "" || responseDirectory == "" || author == "" {
		fmt.Println("Usage: go run main.go -x-api-key <xAPIKey> -json-file-path <jsonFilePath> -url-hostname <urlHostname> -response-file-dir <responseDirectory> -author <author>")
		flag.PrintDefaults()
		return
	}

	saveURLPath := "/api/DpConnection/CallByInterfaceApi/?interfaceCode=ICSiemQueryAct&methodName=Save&culture=en"
	getURLPath := "/api/DpConnection/CallByInterfaceApi/?interfaceCode=ICSiemQueryAct&methodName=GetList&culture=en"

	stat, err := os.Stat(jsonFilePath)
	if err != nil {
		fmt.Println("Error opening JSON file or directory:", err)
		return
	}

	if stat.IsDir() {
		err = filepath.Walk(jsonFilePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(info.Name(), ".json") {
				jsonFile, err := os.Open(path)
				if err != nil {
					return err
				}
				defer jsonFile.Close()

				var savePayload SavePayload
				var getPayload GetPayload
				decoder := json.NewDecoder(jsonFile)
				if err := decoder.Decode(&savePayload.QuerySettings); err != nil {
					fmt.Println("Error decoding JSON file:", err)
					return nil
				}

				// Update the author field in the payload
				savePayload.QuerySettings.Author = author
				// Update the SmartRestRequestContext field in the payload
				savePayload.SmartRestRequestContext = "-<SmartRestRequestContext>-"

				getPayload.Username = author
				getPayload.Filter = savePayload.QuerySettings.Name
				getPayload.SmartRestRequestContext = "-<SmartRestRequestContext>-"

				saveFullURL := fmt.Sprintf("https://%s%s", urlHostname, saveURLPath)
				getFullURL := fmt.Sprintf("https://%s%s", urlHostname, getURLPath)

				err = GetRequest(xAPIKey, getFullURL, "POST", getPayload)
				if err == nil {
					if err := SaveRequest(xAPIKey, saveFullURL, "POST", responseDirectory, savePayload); err != nil {
						fmt.Println(err)
					}
				} else {
					fmt.Println(err)
				}
			}
			return nil
		})
		if err != nil {
			fmt.Println("Error reading JSON files:", err)
		}
	} else {
		jsonFile, err := os.Open(jsonFilePath)
		if err != nil {
			fmt.Println("Error opening JSON file:", err)
			return
		}
		defer jsonFile.Close()

		var savePayload SavePayload
		var getPayload GetPayload

		decoder := json.NewDecoder(jsonFile)
		if err := decoder.Decode(&savePayload.QuerySettings); err != nil {
			fmt.Println("Error decoding JSON file:", err)
			return
		}

		// Update the author field in the payload
		savePayload.QuerySettings.Author = author
		// Update the SmartRestRequestContext field in the payload
		savePayload.SmartRestRequestContext = "-<SmartRestRequestContext>-"

		getPayload.Username = author
		getPayload.Filter = savePayload.QuerySettings.Name
		getPayload.SmartRestRequestContext = "-<SmartRestRequestContext>-"

		saveFullURL := fmt.Sprintf("https://%s%s", urlHostname, saveURLPath)
		getFullURL := fmt.Sprintf("https://%s%s", urlHostname, getURLPath)

		err = GetRequest(xAPIKey, getFullURL, "POST", getPayload)
		if err == nil {
			if err := SaveRequest(xAPIKey, saveFullURL, "POST", responseDirectory, savePayload); err != nil {
				fmt.Println(err)
			}
		} else {
			fmt.Println(err)
		}
	}
}
