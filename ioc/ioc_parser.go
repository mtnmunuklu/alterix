package ioc

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// IOC struct contains IPs, domains, URLs, and hashes.
type IOC struct {
	IPs     []string
	Domains []string
	URLs    []string
	Hashes  []string
}

// checkIfIP checks if the input string is a valid IP address.
func checkIfIP(input string) bool {
	return net.ParseIP(input) != nil
}

// checkIfDomain checks if the input string is a valid domain.
func checkIfDomain(input string) bool {
	domainRegex := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(input)
}

// checkIfURL checks if the input string is a valid URL.
func checkIfURL(input string) bool {
	u, err := url.ParseRequestURI(input)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

// checkIfHash checks if the input string is a valid hash (MD5, SHA1, SHA256).
func checkIfHash(input string) bool {
	hashRegex := regexp.MustCompile(`^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$`)
	return hashRegex.MatchString(input)
}

func classifyInput(input string) (string, map[string][]string) {
	extra := make(map[string][]string)
	switch {
	case checkIfIP(input):
		return "ip", extra
	case checkIfDomain(input):
		return "domain", extra
	case checkIfURL(input):
		u, _ := url.Parse(input)
		host := u.Hostname()
		if checkIfIP(host) {
			extra["ip"] = append(extra["ip"], host)
		} else if checkIfDomain(host) {
			extra["domain"] = append(extra["domain"], host)
		}
		return "url", extra
	case checkIfHash(input):
		return "hash", extra
	default:
		return "unknown", extra
	}
}

func processData(data []byte) (*IOC, error) {
	if len(data) == 0 {
		return nil, errors.New("input data is empty")
	}

	result := &IOC{}
	input := string(data)
	parts := strings.Fields(input)

	if len(parts) == 0 {
		return nil, errors.New("no valid input found")
	}

	for _, part := range parts {
		classification, extra := classifyInput(part)
		switch classification {
		case "ip":
			result.IPs = append(result.IPs, part)
		case "domain":
			result.Domains = append(result.Domains, part)
		case "url":
			result.URLs = append(result.URLs, part)
		case "hash":
			result.Hashes = append(result.Hashes, part)
		}
		for key, items := range extra {
			switch key {
			case "ip":
				result.IPs = append(result.IPs, items...)
			case "domain":
				result.Domains = append(result.Domains, items...)
			}
		}
	}

	return result, nil
}

// ParseIOC parses the input byte slice and returns an IOC struct.
func ParseIOC(input []byte) (*IOC, error) {
	return processData(input)
}
