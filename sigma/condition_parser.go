package sigma

import (
	grammar "github.com/mtnmunuklu/alterix/sigma/internal/grammer"

	"github.com/alecthomas/participle"
	"github.com/alecthomas/participle/lexer"
)

var (
	// Define a lexer that matches the different parts of the Sigma condition syntax
	searchExprLexer = lexer.Must(lexer.Regexp(`(?P<Keyword>(?i)(1 of them)|(all of them)|(1 of)|(all of))` +
		`|(?P<SearchIdentifierPattern>\*?[a-zA-Z_]+\*[a-zA-Z0-9_*]*)` +
		`|(?P<SearchIdentifier>[a-zA-Z_][a-zA-Z0-9_]*)` +
		`|(?P<Operator>(?i)and|or|not|[()])` + // TODO: this never actually matches anything because they get matched as a SearchIdentifier instead. However this isn't currently a problem because we don't parse anything in the Grammar as an Operator (we just use string constants which don't care about Operator vs SearchIdentifier)
		`|(?P<ComparisonOperation>=|!=|<=|>=|<|>)` +
		`|(?P<ComparisonValue>0|[1-9][0-9]*)` +
		`|(?P<Pipe>[|])` +
		`|(\s+)`,
	))

	// Build the parser for the Sigma condition syntax
	searchExprParser = participle.MustBuild(
		&grammar.Condition{},                              // Use the Condition struct defined in the grammar package
		participle.Lexer(searchExprLexer),                 // Use the lexer we defined above
		participle.CaseInsensitive("Keyword", "Operator"), // Make the "Keyword" and "Operator" tokens case-insensitive
	)
)

// Parses the Sigma condition syntax and returns a Condition struct and/or an error
func ParseCondition(input string) (Condition, error) {
	root := grammar.Condition{}
	// Use the searchExprParser to parse the input string into a Condition struct
	if err := searchExprParser.ParseString(input, &root); err != nil {
		return Condition{}, err
	}

	// Convert the parsed search and aggregation expressions into an abstract syntax tree (AST)
	search, err := searchToAST(root.Search)
	if err != nil {
		return Condition{}, err
	}
	aggregation, err := aggregationToAST(root.Aggregation)
	if err != nil {
		return Condition{}, err
	}

	// Return a new Condition struct that contains the ASTs for the search and aggregation expressions
	return Condition{
		Search:      search,
		Aggregation: aggregation,
	}, nil
}
