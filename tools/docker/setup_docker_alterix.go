package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
)

var (
	imageName       string
	containerName   string
	rulesDirectory  string
	configFile      string
	outputDirectory string
)

func init() {
	flag.StringVar(&imageName, "image", "ghcr.io/mtnmunuklu/alterix/alterix:latest", "Name of the Docker image")
	flag.StringVar(&containerName, "container", "alterix", "Name of the Docker container")
	flag.StringVar(&rulesDirectory, "rules", "", "Path to rules directory")
	flag.StringVar(&configFile, "config", "", "Path to config file")
	flag.StringVar(&outputDirectory, "output", "", "Path to output directory")
}

func pullDockerImage() error {
	cmd := exec.Command("docker", "pull", imageName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error pulling Docker image: %w", err)
	}
	return nil
}

func startDockerContainer() error {
	cmd := exec.Command("docker", "run", "-d", "--name", containerName, "-v", rulesDirectory+":/rules", "-v", configFile+":/config", "-v", outputDirectory+":/output", imageName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error starting Docker container: %w", err)
	}
	return nil
}

func main() {
	flag.Parse()

	// Check if the required flags are provided
	if rulesDirectory == "" || configFile == "" || outputDirectory == "" {
		fmt.Println("Usage: go run setup_docker_alterix.go -rules <rulesDirectory> -config <configFile> -output <outputDirectory>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Step 1: Pull Docker image
	if err := pullDockerImage(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Step 2: Start Docker container and mount an output directory
	if err := startDockerContainer(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
