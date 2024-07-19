package ievaluator

import (
	"fmt"
	"net"
	"strings"

	"github.com/mtnmunuklu/alterix/ioc"
)

type IOCEvaluator struct {
	*ioc.IOC
	config        []ioc.Config
	fieldmappings map[string][]string
}

// ForIOC constructs a new IOCEvaluator with the given IOC and evaluation options.
// It applies any provided options to the new IOCEvaluator and returns it.
func ForIOC(ioc *ioc.IOC, options ...Option) *IOCEvaluator {
	e := &IOCEvaluator{IOC: ioc}
	for _, option := range options {
		option(e)
	}
	return e
}

// Result represents the evaluation result of an IOC.
type Result struct {
	QueryResult string   // The query result as a string
	Tags        []string // The list of tags associated with the query
}

// Alters function generates a query string using the IOC information.
func (ioc IOCEvaluator) Alters() (Result, error) {
	var conditions []string
	var tags []string

	// Generate query parts for each field type
	ipConditions := generateCondition(ioc.fieldmappings["ip"], filterUniqueValues(filterValues(ioc.IOC.IPs, checkIfLocalIP)))
	domainConditions := generateCondition(ioc.fieldmappings["domain"], filterUniqueValues(ioc.IOC.Domains))
	urlConditions := generateCondition(ioc.fieldmappings["url"], filterUniqueValues(ioc.IOC.URLs))
	hashConditions := generateCondition(ioc.fieldmappings["hash"], filterUniqueValues(ioc.IOC.Hashes))

	conditions = append(conditions, ipConditions...)
	conditions = append(conditions, domainConditions...)
	conditions = append(conditions, urlConditions...)
	conditions = append(conditions, hashConditions...)

	// Add tags based on the conditions present
	if len(ipConditions) > 0 {
		tags = append(tags, "ip")
	}
	if len(domainConditions) > 0 {
		tags = append(tags, "domain")
	}
	if len(urlConditions) > 0 {
		tags = append(tags, "url")
	}
	if len(hashConditions) > 0 {
		tags = append(tags, "hash")
	}

	// Join the conditions with " or " and wrap in parentheses if there are multiple conditions
	condition := strings.Join(conditions, " or ")
	if len(conditions) > 1 {
		condition = fmt.Sprintf("(%s)", condition)
	}

	query := fmt.Sprintf(`sourcetype="*" eql select * from _source_ where _condition_ and %s`, condition)
	result := Result{
		QueryResult: query,
		Tags:        tags,
	}

	return result, nil
}

// generateCondition generates the condition part of the query for a given field and values.
func generateCondition(fields []string, values []string) []string {
	var conditions []string
	for _, field := range fields {
		var condition string
		if len(values) == 1 {
			condition = fmt.Sprintf("%s='%s'", field, values[0])
		} else if len(values) > 1 {
			condition = fmt.Sprintf("%s in (%s)", field, joinValues(values))
		}
		if condition != "" {
			conditions = append(conditions, condition)
		}
	}
	return conditions
}

// joinValues joins a slice of values into a single comma-separated string with quotes.
func joinValues(values []string) string {
	quotedValues := make([]string, len(values))
	for i, v := range values {
		quotedValues[i] = fmt.Sprintf("'%s'", v)
	}
	return strings.Join(quotedValues, ", ")
}

// checkIfLocalIP checks if the provided IP address is a local IP.
func checkIfLocalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	if parsedIP.IsLoopback() || parsedIP.IsPrivate() {
		return true
	}
	return false
}

// filterValues filters out values based on the provided filter function.
func filterValues(values []string, filterFunc func(string) bool) []string {
	var filteredValues []string
	for _, value := range values {
		if !filterFunc(value) {
			filteredValues = append(filteredValues, value)
		}
	}
	return filteredValues
}

// filterUniqueValues filters out duplicate values from the provided slice.
func filterUniqueValues(values []string) []string {
	valueSet := make(map[string]struct{})
	var uniqueValues []string
	for _, value := range values {
		if _, exists := valueSet[value]; !exists {
			valueSet[value] = struct{}{}
			uniqueValues = append(uniqueValues, value)
		}
	}
	return uniqueValues
}
