package grammar

// Aggregation represents a struct for grouping and aggregating data
type Aggregation struct {
	// Function holds the aggregation function used in the aggregation
	Function AggregationFunction `@@`

	// AggregationField holds the field used in the aggregation
	AggregationField string `("(" (@SearchIdentifier)? ")")?`

	// GroupField holds the field used for grouping data
	GroupField string `("by" @SearchIdentifier)?`

	// Comparison holds the comparison operator used in the aggregation
	Comparison *ComparisonOp `(@@`

	// Threshold holds the threshold value used in the aggregation comparison
	Threshold float64 `@ComparisonValue)?`
}

// AggregationFunction represents the type of aggregation function
type AggregationFunction struct {
	Count bool `@"count"`
	Min   bool `| @"min"`
	Max   bool `| @"max"`
	Avg   bool `| @"avg"`
	Sum   bool `| @"sum"`
}

// ComparisonOp represents the type of comparison operator used in the aggregation
type ComparisonOp struct {
	Equal            bool `@"="`
	NotEqual         bool `| @"!="`
	LessThan         bool `| @"<"`
	LessThanEqual    bool `| @"<="`
	GreaterThan      bool `| @">"`
	GreaterThanEqual bool `| @">="`
}
