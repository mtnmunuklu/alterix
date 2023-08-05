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

type Data struct {
	TimeFrameValue            int    `json:"TimeFrameValue"`
	TimeFrameType             string `json:"TimeFrameType"`
	RuleType                  string `json:"RuleType"`
	QueryCorrelationAlertType string `json:"QueryCorrelationAlertType"`
	QueryID                   string `json:"QueryID"`
	Query                     string `json:"Query"`
}

type Correlation struct {
	Name            string   `json:"Name"`
	Description     string   `json:"Description"`
	Tags            []string `json:"Tags"`
	MaxAlertCount   int      `json:"MaxAlertCount"`
	RiskLevel       int      `json:"RiskLevel"`
	CorrelationType string   `json:"CorrelationType"`
	Data            Data     `json:"Data"`
	Enabled         bool     `json:"Enabled"`
	Message         string   `json:"Message"`
}

type SavePayload struct {
	Correlation             Correlation `json:"correlation"`
	SmartRestRequestContext string      `json:"smartRestRequestContext"`
}

type GetPayload struct {
	Filter                  string `json:"filter"`
	SmartRestRequestContext string `json:"smartRestRequestContext"`
}

var (
	xAPIKey           string
	jsonFilePath      string
	urlHostname       string
	responseDirectory string
)

func init() {
	flag.StringVar(&xAPIKey, "x-api-key", "", "API key for authentication")
	flag.StringVar(&jsonFilePath, "json-file-path", "", "Path to the JSON file or directory containing JSON files")
	flag.StringVar(&urlHostname, "url-hostname", "", "Hostname of the URL")
	flag.StringVar(&responseDirectory, "response-file-dir", "", "Directory to save response files")
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

	// Create a filename using the value of the "Name" field
	filename := fmt.Sprintf("%s.json", savePayload.Correlation.Name)

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

func processJSONPayload(payload map[string]interface{}) (SavePayload, GetPayload, error) {
	var savePayload SavePayload
	var getPayload GetPayload

	savePayload.Correlation.Name = payload["query"].(map[string]interface{})["Name"].(string)
	savePayload.Correlation.Description = payload["query"].(map[string]interface{})["Description"].(string)
	savePayload.Correlation.Tags = toStringSlice(payload["query"].(map[string]interface{})["Tags"].([]interface{}))
	savePayload.Correlation.MaxAlertCount = 5
	savePayload.Correlation.RiskLevel = int(payload["query"].(map[string]interface{})["RiskLevel"].(float64))
	savePayload.Correlation.CorrelationType = "Interface IQueryCorrelation"
	savePayload.Correlation.Data.TimeFrameValue = 5
	savePayload.Correlation.Data.TimeFrameType = "minutes"
	savePayload.Correlation.Data.RuleType = "any"
	savePayload.Correlation.Data.QueryCorrelationAlertType = "WhenOneOrMoreRow"
	savePayload.Correlation.Data.QueryID = payload["query"].(map[string]interface{})["ID"].(string)
	savePayload.Correlation.Data.Query = payload["query"].(map[string]interface{})["Query"].(string)
	savePayload.Correlation.Enabled = true
	savePayload.Correlation.Message = savePayload.Correlation.Name
	// Update the SmartRestRequestContext field in the payload
	savePayload.SmartRestRequestContext = "-<SmartRestRequestContext>-"

	getPayload.Filter = savePayload.Correlation.Name
	getPayload.SmartRestRequestContext = "-<SmartRestRequestContext>-"

	return savePayload, getPayload, nil
}

func toStringSlice(data []interface{}) []string {
	result := make([]string, len(data))
	for i, val := range data {
		result[i] = val.(string)
	}
	return result
}

func main() {
	if xAPIKey == "" || jsonFilePath == "" || urlHostname == "" || responseDirectory == "" {
		fmt.Println("Usage: go run main.go -x-api-key <xAPIKey> -json-file-path <jsonFilePath> -url-hostname <urlHostname> -response-file-dir <responseDirectory>")
		flag.PrintDefaults()
		return
	}

	saveURLPath := "/api/DpConnection/CallByInterfaceApi/?interfaceCode=ICSiemManagerCorrelationAct&methodName=AddOrUpdateCorrelation&culture=en"
	getURLPath := "/api/DpConnection/CallByInterfaceApi/?interfaceCode=ICSiemManagerCorrelationAct&methodName=GetCorrelationList&culture=en"

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

				var payload map[string]interface{}
				decoder := json.NewDecoder(jsonFile)
				if err := decoder.Decode(&payload); err != nil {
					fmt.Println("Error decoding JSON file:", err)
					return nil
				}

				savePayload, getPayload, err := processJSONPayload(payload)
				if err != nil {
					fmt.Println("Error processing JSON payload:", err)
					return nil
				}

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

		var payload map[string]interface{}
		decoder := json.NewDecoder(jsonFile)
		if err := decoder.Decode(&payload); err != nil {
			fmt.Println("Error decoding JSON file:", err)
			return
		}

		savePayload, getPayload, err := processJSONPayload(payload)
		if err != nil {
			fmt.Println("Error processing JSON payload:", err)
			return
		}

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
