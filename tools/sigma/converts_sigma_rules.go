package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GitHub repository properties
const (
	repositoryOwner  = "SigmaHQ"
	repositoryName   = "sigma"
	projectFolder    = "sigma_project"
	sigmaRulesFolder = "rules"
)

// RuleInfo stores information about a rule
type RuleInfo struct {
	Path string `json:"path"`
	Hash string `json:"hash"`
}

var previousFiles map[string]RuleInfo
var previousFilesPath, alterixPath, alterixConfigPath, alterixOutputDir string
var useDocker bool

func init() {
	if len(os.Args) < 5 {
		fmt.Println("Usage: go run main.go -previous-files-path <previous-files-path> -alterix-path <alterix-path> -alterix-config-path <alterix-config-path> -alterix-output-dir <alterix-output-dir> -use-docker")
		os.Exit(1)
	}

	flag.StringVar(&previousFilesPath, "previous-files-path", "", "Path to previous files")
	flag.StringVar(&alterixPath, "alterix-path", "", "Path to Alterix")
	flag.StringVar(&alterixConfigPath, "alterix-config-path", "", "Path to Alterix configuration file")
	flag.StringVar(&alterixOutputDir, "alterix-output-dir", "", "Directory to save Alterix output")
	flag.BoolVar(&useDocker, "use-docker", false, "Whether to use Docker to run Alterix")

	flag.Parse()

	if previousFilesPath == "" || alterixPath == "" || alterixConfigPath == "" || alterixOutputDir == "" {
		fmt.Println("Error: All flags are required.")
		os.Exit(1)
	}

	previousFiles = GetPreviousFiles()
}

func CloneOrPullProject() {
	if _, err := os.Stat(projectFolder); os.IsNotExist(err) {
		cmd := exec.Command("git", "clone", fmt.Sprintf("https://github.com/%s/%s.git", repositoryOwner, repositoryName), projectFolder)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println("Error cloning the project:", err)
			os.Exit(1)
		}
	} else {
		os.Chdir(projectFolder)
		cmd := exec.Command("git", "pull")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println("Error pulling the project:", err)
			os.Exit(1)
		}
	}
}

func CalculateFileHash(filePath string) (string, error) {
	sha256Hash := ""
	file, err := os.Open(filePath)
	if err != nil {
		return sha256Hash, err
	}
	defer file.Close()

	sha256Hasher := sha256.New()
	if _, err := io.Copy(sha256Hasher, file); err != nil {
		return sha256Hash, err
	}

	sha256Hash = hex.EncodeToString(sha256Hasher.Sum(nil))
	return sha256Hash, nil
}

func CheckSigmaRules() ([]string, []string) {
	changedRules := []string{}
	newRules := []string{}

	err := filepath.Walk(sigmaRulesFolder, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".yml") {
			relativePath, err := filepath.Rel(projectFolder, filePath)
			if err != nil {
				return err
			}

			ruleName := strings.TrimSuffix(info.Name(), ".yml")
			fileHash, err := CalculateFileHash(filePath)
			if err != nil {
				return err
			}

			if ruleInfo, exists := previousFiles[ruleName]; exists {
				if ruleInfo.Hash != fileHash {
					changedRules = append(changedRules, relativePath)
				}
			} else {
				newRules = append(newRules, relativePath)
			}

			previousFiles[ruleName] = RuleInfo{
				Path: relativePath,
				Hash: fileHash,
			}
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error checking Sigma rules:", err)
		os.Exit(1)
	}

	return changedRules, newRules
}

func GetPreviousFiles() map[string]RuleInfo {
	previousFiles := map[string]RuleInfo{}
	if _, err := os.Stat(previousFilesPath); err == nil {
		data, err := os.ReadFile(previousFilesPath)
		if err != nil {
			fmt.Println("Error reading previous files:", err)
			os.Exit(1)
		}
		err = json.Unmarshal(data, &previousFiles)
		if err != nil {
			fmt.Println("Error decoding previous files:", err)
			os.Exit(1)
		}
	}
	return previousFiles
}

func SavePreviousFiles() {
	data, err := json.MarshalIndent(previousFiles, "", "    ")
	if err != nil {
		fmt.Println("Error encoding previous files:", err)
		os.Exit(1)
	}
	err = os.WriteFile(previousFilesPath, data, 0644)
	if err != nil {
		fmt.Println("Error writing previous files to disk:", err)
		os.Exit(1)
	}
}

func RunAlterix(inputData map[string][]string) {
	for _, rulePath := range inputData["changed_rules"] {
		if useDocker {
			cmd := exec.Command("docker", "exec", "alterix", "./alterix", "-filepath", rulePath, "-config", alterixConfigPath, "-json", "-output", alterixOutputDir)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			if err != nil {
				fmt.Println("Error running ALTERIX:", err)
			}
		} else {
			cmd := exec.Command(alterixPath, "-filepath", rulePath, "-config", alterixConfigPath, "-json", "-output", alterixOutputDir)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			if err != nil {
				fmt.Println("Error running ALTERIX:", err)
			}
		}
	}

	for _, rulePath := range inputData["new_rules"] {
		if useDocker {
			cmd := exec.Command("docker", "exec", "alterix", "./alterix", "-filepath", rulePath, "-config", alterixConfigPath, "-json", "-output", alterixOutputDir)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			if err != nil {
				fmt.Println("Error running ALTERIX:", err)
			}
		} else {
			cmd := exec.Command(alterixPath, "-filepath", rulePath, "-config", alterixConfigPath, "-json", "-output", alterixOutputDir)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			if err != nil {
				fmt.Println("Error running ALTERIX:", err)
			}
		}
	}
}

func main() {
	// Clone or pull the project from GitHub
	CloneOrPullProject()

	// Check for changes in the Sigma rules
	changedRules, newRules := CheckSigmaRules()

	// If both changedRules and newRules are empty, exit the program
	if len(changedRules) == 0 && len(newRules) == 0 {
		fmt.Println("No changes or new rules found.")
		return
	}

	// Save the updated dictionary of previous files and their hashes
	SavePreviousFiles()

	// Prepare input data for ALTERIX
	inputData := map[string][]string{
		"changed_rules": changedRules,
		"new_rules":     newRules,
	}

	// Run ALTERIX with the generated JSON object as input
	RunAlterix(inputData)
}
