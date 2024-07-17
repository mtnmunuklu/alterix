package ievaluator

import (
	"fmt"
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
	ipConditions := generateCondition(ioc.fieldmappings["ip"], ioc.IOC.IPs)
	domainConditions := generateCondition(ioc.fieldmappings["domain"], ioc.IOC.Domains)
	urlConditions := generateCondition(ioc.fieldmappings["url"], ioc.IOC.URLs)
	hashConditions := generateCondition(ioc.fieldmappings["hash"], ioc.IOC.Hashes)

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

	// Join the conditions with " OR " and wrap in parentheses if there are multiple conditions
	condition := strings.Join(conditions, " OR ")
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
			condition = fmt.Sprintf("%s = '%s'", field, values[0])
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
