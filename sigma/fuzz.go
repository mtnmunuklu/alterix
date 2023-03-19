package sigma

// Try parsing the input data as a Sigma rule, return 0 if it fails (no match), 1 otherwise (match)
func FuzzRuleParser(data []byte) int {
	_, err := ParseRule(data)
	if err != nil {
		return 0
	}
	return 1
}

// Try parsing the input data as a Sigma condition, return 0 if it fails (no match), 1 otherwise (match)
func FuzzConditionParser(data []byte) int {
	_, err := ParseCondition(string(data))
	if err != nil {
		return 0
	}
	return 1
}

// Try parsing the input data as a Sigma config file, return 0 if it fails (no match), 1 otherwise (match)
func FuzzConfigParser(data []byte) int {
	_, err := ParseConfig(data)
	if err != nil {
		return 0
	}
	return 1
}
