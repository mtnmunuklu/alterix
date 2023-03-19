package grammar

type Condition struct {
	Search      Disjunction  `@@`        // Represents the search condition
	Aggregation *Aggregation `("|" @@)?` // Represents an optional aggregation function and its parameters
}

type Disjunction struct {
	Nodes []*Conjunction `@@ ("or" @@)*` // Represents a disjunction of conjunctions
}

type Conjunction struct {
	Nodes []*Term `@@ ("and" @@)*` // Represents a conjunction of terms
}

type Term struct {
	Negated       *Term        `"not" @@`            // Represents a negation of a term
	OneAllOf      *OneAllOf    `| @@`                // Represents a one-of or all-of pattern
	Identifer     *string      `| @SearchIdentifier` // Represents a search identifier
	Subexpression *Disjunction `| "(" @@ ")"`        // Represents a subexpression
}

type OneAllOf struct {
	OneOfIdentifier *string `"1 of" @SearchIdentifier`            // Represents a one-of identifier
	AllOfIdentifier *string `| "all of" @SearchIdentifier`        // Represents an all-of identifier
	OneOfPattern    *string `| "1 of" @SearchIdentifierPattern`   // Represents a one-of pattern
	AllOfPattern    *string `| "all of" @SearchIdentifierPattern` // Represents an all-of pattern
	OneOfThem       bool    `| @("1 of them")`                    // Represents the "1 of them" keyword
	ALlOfThem       bool    `| @("all of them")`                  // Represents the "all of them" keyword
}
