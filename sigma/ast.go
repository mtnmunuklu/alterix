package sigma

import (
	"fmt"
	"strings"

	grammar "github.com/mtnmunuklu/alterix/sigma/internal/grammer"
	"gopkg.in/yaml.v3"
)

type Condition struct {
	node        *yaml.Node
	Search      SearchExpr      // represents the search query
	Aggregation AggregationExpr // represents the aggregation operation
}

// This function is used to convert a Condition struct to YAML format.
// It takes the Condition struct and returns its YAML representation.
func (c Condition) MarshalYAML() (interface{}, error) {
	// First, convert the Search expression to its string representation
	search := c.Search.toString()

	// If an Aggregation expression is present, add it to the string representation of the Search expression
	if c.Aggregation != nil {
		return search + " | " + c.Aggregation.toString(), nil
	} else {
		return search, nil
	}
}

// Position returns the line and column of this Condition in the original input
func (c Condition) Position() (int, int) {
	return c.node.Line - 1, c.node.Column - 1
}

// SearchExpr is an interface that represents a search expression.
type SearchExpr interface {
	searchExpr()      // searchExpr is an empty marker method used to identify types that implement the SearchExpr interface.
	toString() string // toString converts the search expression to a string.
}

// And is a type that represents a list of search expressions that are connected with the "and" operator.
type And []SearchExpr

// searchExpr is a method that implements the SearchExpr interface.
func (And) searchExpr() {}

// toString is a method that returns the string representation of the And expression.
func (e And) toString() string {
	// If there is only one expression in the list, return its string representation directly.
	if len(e) == 1 {
		return e[0].toString()
	} else {
		// Convert all the sub-expressions to string.
		converted := make([]string, len(e))
		for idx, sub := range e {
			converted[idx] = sub.toString()
		}
		// Join the sub-expressions with the "and" operator and wrap them in parentheses.
		return "(" + strings.Join(converted, " and ") + ")"
	}
}

// Or is a slice of SearchExpr representing a logical "or" operation between multiple search expressions.
type Or []SearchExpr

// searchExpr is a method that implements the SearchExpr interface. It is used to mark an Or instance as a valid SearchExpr.
func (Or) searchExpr() {}

// toString is a method that returns the string representation of an Or instance.
// It combines the string representation of all the SearchExpr instances in the slice using the "or" logical operator.
func (e Or) toString() string {
	// If the length of the Or slice is 1, we simply call toString on the single element.
	if len(e) == 1 {
		return e[0].toString()
	} else {
		// Otherwise, we iterate over each element in the slice and call toString on each element,
		// then concatenate them using " or " as the separator and enclose the entire expression in parentheses.
		converted := make([]string, len(e))
		for idx, sub := range e {
			converted[idx] = sub.toString()
		}
		return "(" + strings.Join(converted, " or ") + ")"
	}
}

// Not struct represents a negation of a search expression.
type Not struct {
	Expr SearchExpr // The search expression to be negated.
}

// toString method returns a string representation of the negated search expression.
func (e Not) toString() string {
	return "not " + e.Expr.toString()
}

// searchExpr method implements the SearchExpr interface.
// It is used to mark the Not struct as a search expression.
func (Not) searchExpr() {}

// OneOfIdentifier represents an expression that matches one of the search identifiers.
type OneOfIdentifier struct {
	Ident SearchIdentifier
}

// searchExpr is a method of the OneOfIdentifier type that implements the SearchExpr interface.
// Since OneOfIdentifier is a search expression, this method must exist to satisfy the interface.
func (OneOfIdentifier) searchExpr() {}

// toString is a method of the OneOfIdentifier type that returns the string representation of the expression.
// It returns a string in the format "1 of [identifier]".
func (e OneOfIdentifier) toString() string {
	return "1 of " + e.Ident.toString()
}

// AllOfIdentifier is a struct representing a search expression that matches documents containing all of the specified identifiers.
type AllOfIdentifier struct {
	Ident SearchIdentifier
}

// searchExpr is a method of AllOfIdentifier that implements the SearchExpr interface.
// It is used to mark AllOfIdentifier as a valid search expression.
func (AllOfIdentifier) searchExpr() {}

// toString is a method of AllOfIdentifier that returns a string representation of the search expression.
// It returns a string in the format "all of {identifiers}", where {identifiers} is the result of calling toString() on the SearchIdentifier.
func (e AllOfIdentifier) toString() string {
	return "all of " + e.Ident.toString()
}

// AllOfPattern defines a struct that represents a search query for all occurrences of a given pattern
type AllOfPattern struct {
	Pattern string
}

// searchExpr is a method of the SearchExpr interface that is implemented by AllOfPattern
func (AllOfPattern) searchExpr() {}

// toString is a method that returns the string representation of the search query
func (e AllOfPattern) toString() string {
	return "all of " + e.Pattern
}

// OneOfPattern represents a search expression that matches one of the search patterns.
type OneOfPattern struct {
	Pattern string
}

// searchExpr is a method for satisfying the SearchExpr interface.
func (OneOfPattern) searchExpr() {}

// toString is a method that returns a string representation of the search expression.
func (e OneOfPattern) toString() string {
	return "1 of " + e.Pattern
}

// OneOfThem is a struct representing a search expression that matches if exactly one search result is matched.
type OneOfThem struct{}

// searchExpr is a method of the OneOfThem struct that indicates it implements the SearchExpr interface.
func (OneOfThem) searchExpr() {}

// toString is a method of the OneOfThem struct that returns a string representation of the search expression.
func (OneOfThem) toString() string {
	return "1 of them"
}

// AllOfThem is a struct that represents a search expression for all of the items matching the search criteria.
type AllOfThem struct{}

// searchExpr is a method of AllOfThem that satisfies the SearchExpr interface, but does not perform any action.
func (AllOfThem) searchExpr() {}

// toString is a method of AllOfThem that returns the string representation of the search expression for all of the items.
func (AllOfThem) toString() string {
	return "all of them"
}

// SearchIdentifier represents a search identifier, which is simply a string.
type SearchIdentifier struct {
	Name string // The name of the identifier.
}

// searchExpr is a function of the SearchExpr interface implemented by SearchIdentifier.
// It does not perform any actual search operation and is only included to satisfy the interface.
func (SearchIdentifier) searchExpr() {}

// toString returns the string representation of the SearchIdentifier.
func (e SearchIdentifier) toString() string {
	return e.Name
}

// Define the AggregationExpr interface with two methods.
type AggregationExpr interface {
	aggregationExpr()
	toString() string
}

// Define the Near struct with a Condition field.
type Near struct {
	Condition SearchExpr
}

// Implement the aggregationExpr method for the Near struct.
func (Near) aggregationExpr() {}

// Implement the toString method for the Near struct.
func (n Near) toString() string {
	// Return a string representation of the Near struct.
	// This includes the "near" keyword followed by the string representation of the condition.
	return "near " + n.Condition.toString()
}

// ComparisonOp represents the comparison operators used in comparisons
type ComparisonOp string

// Define the different comparison operators as constants
var (
	Equal            ComparisonOp = "="
	NotEqual         ComparisonOp = "!="
	LessThan         ComparisonOp = "<"
	LessThanEqual    ComparisonOp = "<="
	GreaterThan      ComparisonOp = ">"
	GreaterThanEqual ComparisonOp = ">="
)

// Comparison represents a comparison expression that applies a comparison operator to an aggregation result
type Comparison struct {
	Func      AggregationFunc // the aggregation function to apply
	Op        ComparisonOp    // the comparison operator to use
	Threshold float64         // the threshold value to compare against
}

// aggregationExpr is a marker function indicating that Comparison implements the AggregationExpr interface
func (Comparison) aggregationExpr() {}

// toString returns a string representation of the Comparison expression
func (e Comparison) toString() string {
	return fmt.Sprintf("%v %v %v", e.Func.toString(), e.Op, e.Threshold)
}

// AggregationFunc is an interface for defining aggregation functions.
type AggregationFunc interface {
	aggregationFunc() // an empty function to identify this interface
	toString() string // a function to convert the function to a string representation
}

// Count represents a count aggregation function.
type Count struct {
	Field     string // the field to count
	GroupedBy string // the field to group by
}

// aggregationFunc is an empty function used to identify Count as an AggregationFunc.
func (Count) aggregationFunc() {}

// toString returns a string representation of the Count function.
func (c Count) toString() string {
	result := "count(" + c.Field + ")"
	if c.GroupedBy != "" {
		result += " by " + c.GroupedBy
	}
	return result
}

// Min represents the minimum aggregation function.
type Min struct {
	Field     string // Field to apply the aggregation on
	GroupedBy string // Optional field to group the aggregation by
}

// aggregationFunc is a method of the AggregationFunc interface, used to signify that this
// struct represents an aggregation function.
func (Min) aggregationFunc() {}

// toString is a method of the AggregationFunc interface, used to generate a string
// representation of the aggregation function.
func (c Min) toString() string {
	result := "min(" + c.Field + ")"
	if c.GroupedBy != "" {
		result += " by " + c.GroupedBy
	}
	return result
}

// Max is a type that represents a maximum aggregation function.
type Max struct {
	Field     string // The field to apply the max function to.
	GroupedBy string // The field to group the results by.
}

// aggregationFunc is a method that implements the AggregationFunc interface for Max.
func (Max) aggregationFunc() {}

// toString is a method that returns a string representation of the Max aggregation.
// If GroupedBy is not empty, the result will be "max(Field) by GroupedBy",
// otherwise it will be "max(Field)".
func (c Max) toString() string {
	result := "max(" + c.Field + ")"
	if c.GroupedBy != "" {
		result += " by " + c.GroupedBy
	}
	return result
}

// Average represents an aggregation function that calculates the average of a field.
type Average struct {
	Field     string // The field to be averaged.
	GroupedBy string // Optional field to group the results by.
}

// aggregationFunc is a method of the AggregationFunc interface, and does nothing here.
func (Average) aggregationFunc() {}

// toString is a method of the AggregationFunc interface that returns the string representation of the function.
func (c Average) toString() string {
	result := "avg(" + c.Field + ")"
	if c.GroupedBy != "" {
		result += " by " + c.GroupedBy
	}
	return result
}

// The Sum type represents an aggregation function that calculates the sum of a field.
type Sum struct {
	Field     string // The name of the field to sum.
	GroupedBy string // The name of the field to group by, if any.
}

// The aggregationFunc method is used to mark the Sum type as an AggregationFunc.
// This method does not have any implementation, as its purpose is simply to satisfy the AggregationFunc interface.
func (Sum) aggregationFunc() {}

// The toString method returns a string representation of the Sum aggregation function.
func (c Sum) toString() string {
	// Start with the "sum" keyword, followed by the name of the field to sum.
	result := "sum(" + c.Field + ")"

	// If the GroupedBy field is not empty, add the "by" keyword and the name of the field to group by.
	if c.GroupedBy != "" {
		result += " by " + c.GroupedBy
	}

	// Return the final string representation of the Sum aggregation function.
	return result
}

func searchToAST(node interface{}) (SearchExpr, error) {
	switch n := node.(type) {

	// If the current node is a disjunction
	case grammar.Disjunction:
		// If there is only one node in the disjunction, ignore the disjunction and move on to the node
		if len(n.Nodes) == 1 {
			return searchToAST(*n.Nodes[0])
		}

		// Create a new OR expression and iterate through each node in the disjunction
		or := Or{}
		for _, node := range n.Nodes {
			// Recursively convert each node to an AST
			n, err := searchToAST(*node)
			if err != nil {
				return nil, err
			}
			// Add the resulting AST to the OR expression
			or = append(or, n)
		}
		return or, nil

	// If the current node is a conjunction
	case grammar.Conjunction:
		// If there is only one node in the conjunction, ignore the conjunction and move on to the node
		if len(n.Nodes) == 1 {
			return searchToAST(*n.Nodes[0])
		}

		// Create a new AND expression and iterate through each node in the conjunction
		and := And{}
		for _, node := range n.Nodes {
			// Recursively convert each node to an AST
			n, err := searchToAST(*node)
			if err != nil {
				return nil, err
			}
			// Add the resulting AST to the AND expression
			and = append(and, n)
		}
		return and, nil

	// If the current node is a term
	case grammar.Term:
		switch {
		// If the term is negated, convert the negated node to an AST and create a NOT expression with it
		case n.Negated != nil:
			n, err := searchToAST(*n.Negated)
			if err != nil {
				return nil, err
			}
			return Not{Expr: n}, nil

		// If the term is an identifier, create a SearchIdentifier expression with the identifier name
		case n.Identifer != nil:
			return SearchIdentifier{Name: *n.Identifer}, nil

		// If the term is a subexpression, recursively convert the subexpression node to an AST
		case n.Subexpression != nil:
			return searchToAST(*n.Subexpression)

		// If the term is an "one of" expression, create the appropriate expression based on its type
		case n.OneAllOf != nil:
			o := n.OneAllOf
			switch {

			// If the "one of" expression is "all of them", create an AllOfThem expression
			case o.ALlOfThem:
				return AllOfThem{}, nil

			// If the "one of" expression is "one of them", create a OneOfThem expression
			case o.OneOfThem:
				return OneOfThem{}, nil

			// If the "one of" expression is an "all of" expression with an identifier, create an AllOfIdentifier expression with the identifier name
			case o.AllOfIdentifier != nil:
				return AllOfIdentifier{
					Ident: SearchIdentifier{Name: *o.AllOfIdentifier},
				}, nil

			// If the "one of" expression is a "one of" expression with an identifier, create a OneOfIdentifier expression with the identifier name
			case o.OneOfIdentifier != nil:
				return OneOfIdentifier{
					Ident: SearchIdentifier{Name: *o.OneOfIdentifier},
				}, nil

			// If the "one of" expression is an "all of" expression with a pattern, create an AllOfPattern
			case o.AllOfPattern != nil:
				return AllOfPattern{
					Pattern: *o.AllOfPattern,
				}, nil

			// If the "one of" expression is a "one of" expression with a pattern, create a OneOfPattern expression with the pattern
			case o.OneOfPattern != nil:
				return OneOfPattern{
					Pattern: *o.OneOfPattern,
				}, nil

			// If none of the "one of" expressions match, return an error
			default:
				return nil, fmt.Errorf("invalid term type: all fields nil")
			}

		// If the term is not a "one of" expression, return an error
		default:
			return nil, fmt.Errorf("invalid term")
		}

	// If the node is not a disjunction, conjunction, or term, return an error
	default:
		return nil, fmt.Errorf("unhandled node type %T", node)
	}
}

// aggregationToAST converts a grammar.Aggregation to an AggregationExpr
// which is part of the AST.
func aggregationToAST(agg *grammar.Aggregation) (AggregationExpr, error) {
	// If the aggregation is nil, return nil as the AST representation.
	if agg == nil {
		return nil, nil
	}

	// Define an AggregationFunc variable to hold the type of aggregation function
	var function AggregationFunc

	// Determine the type of aggregation function and assign it to the function variable
	switch {
	case agg.Function.Count:
		function = Count{
			Field:     agg.AggregationField,
			GroupedBy: agg.GroupField,
		}
	case agg.Function.Min:
		function = Min{
			Field:     agg.AggregationField,
			GroupedBy: agg.GroupField,
		}
	case agg.Function.Max:
		function = Max{
			Field:     agg.AggregationField,
			GroupedBy: agg.GroupField,
		}
	case agg.Function.Avg:
		function = Average{
			Field:     agg.AggregationField,
			GroupedBy: agg.GroupField,
		}
	case agg.Function.Sum:
		function = Sum{
			Field:     agg.AggregationField,
			GroupedBy: agg.GroupField,
		}
	default:
		// If the type of aggregation function is not recognized, return an error.
		return nil, fmt.Errorf("unknown aggregation function")
	}

	// If the aggregation is not a comparison, return an error as non comparison aggregations are not yet supported.
	if agg.Comparison == nil {
		return nil, fmt.Errorf("non comparison aggregations not yet supported")
	}

	// Define a ComparisonOp variable to hold the type of comparison operation
	var operation ComparisonOp

	// Determine the type of comparison operation and assign it to the operation variable
	switch {
	case agg.Comparison.Equal:
		operation = Equal
	case agg.Comparison.NotEqual:
		operation = NotEqual
	case agg.Comparison.LessThan:
		operation = LessThan
	case agg.Comparison.LessThanEqual:
		operation = LessThanEqual
	case agg.Comparison.GreaterThan:
		operation = GreaterThan
	case agg.Comparison.GreaterThanEqual:
		operation = GreaterThanEqual
	default:
		// If the type of comparison operation is not recognized, return an error.
		return nil, fmt.Errorf("unknown operation %v", agg.Comparison)
	}

	// Create a Comparison expression with the function, operation and threshold fields
	return Comparison{
		Func:      function,
		Op:        operation,
		Threshold: agg.Threshold,
	}, nil
}
