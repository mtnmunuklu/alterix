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
}

type Payload struct {
	QuerySettings           QuerySettings `json:"querySettings"`
	SmartRestRequestContext string        `json:"smartRestRequestContext"`
}

var (
	xAPIKey           string
	jsonFilePath      string
	urlHostname       string
	responseDirectory string
	author            string
	urlPath           string
)

func init() {
	flag.StringVar(&xAPIKey, "x-api-key", "", "API key for authentication")
	flag.StringVar(&jsonFilePath, "json-file-path", "", "Path to the JSON file or directory containing JSON files")
	flag.StringVar(&urlHostname, "url-hostname", "", "Hostname of the URL")
	flag.StringVar(&responseDirectory, "response-file-dir", "", "Directory to save response files")
	flag.StringVar(&author, "author", "", "Author to update in the payload")
	flag.StringVar(&urlPath, "url-path", "/api/DpConnection/CallByInterfaceApi/?interfaceCode=ICSiemQueryAct&methodName=Save&culture=en", "Path of the URL")
	flag.Parse()
}

func SendRequest(xAPIKey, url, method string, payload Payload, responseDirectory string) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshaling JSON payload: %w", err)
	}

	req, err := http.NewRequest(method, url, strings.NewReader(string(payloadBytes)))
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

	// Create a filename using the value of the "Name" field
	filename := fmt.Sprintf("%s.json", payload.QuerySettings.Name)

	// Write the JSON response to a file
	responseFilePath := filepath.Join(responseDirectory, filename)
	err = writeJSONToFile(responseFilePath, body)
	if err != nil {
		return fmt.Errorf("error writing JSON response to file: %w", err)
	}

	fmt.Printf("Response received and saved to %s\n", responseFilePath)
	return nil
}

func writeJSONToFile(filename string, data []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
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

				var payload Payload
				decoder := json.NewDecoder(jsonFile)
				if err := decoder.Decode(&payload.QuerySettings); err != nil {
					fmt.Println("Error decoding JSON file:", err)
					return nil
				}

				// Update the author field in the payload
				payload.QuerySettings.Author = author
				// Update the SmartRestRequestContext field in the payload
				payload.SmartRestRequestContext = "-<SmartRestRequestContext>-"

				fullURL := fmt.Sprintf("https://%s%s", urlHostname, urlPath)
				if err := SendRequest(xAPIKey, fullURL, "POST", payload, responseDirectory); err != nil {
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

		var payload Payload
		decoder := json.NewDecoder(jsonFile)
		if err := decoder.Decode(&payload.QuerySettings); err != nil {
			fmt.Println("Error decoding JSON file:", err)
			return
		}

		// Update the author field in the payload
		payload.QuerySettings.Author = author
		// Update the SmartRestRequestContext field in the payload
		payload.SmartRestRequestContext = "-<SmartRestRequestContext>-"

		fullURL := fmt.Sprintf("https://%s%s", urlHostname, urlPath)
		if err := SendRequest(xAPIKey, fullURL, "POST", payload, responseDirectory); err != nil {
			fmt.Println(err)
		}
	}
}
