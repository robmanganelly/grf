// # Usage
//
//	import "github.com/robmanganelly/grf/internal/operators"
//
//	// Parse from query string
//	op, ok := operators.Parse("eq")
//	if ok {
//	    fmt.Println(op.Category())    // "equality"
//	    fmt.Println(op.Description()) // "equals"
//	}
//	// Use constants directly
//	if op == operators.Equal {
//	    // handle equality
//	}
//	// Get all numeric operators
//	numericOps := operators.ByCategory(operators.CategoryNumeric)
package operators

// Category represents the category of an operator
type Category string

const (
	CategoryEquality Category = "equality"
	CategoryNumeric  Category = "numeric"
	CategoryRange    Category = "range"
	CategorySet      Category = "set"
	CategoryText     Category = "text"
)

// Operator represents a filter operator
type Operator string

// Equality operators
const (
	Equal    Operator = "eq"
	NotEqual Operator = "ne"
)

// Numeric operators
const (
	GreaterThan        Operator = "gt"
	GreaterThanOrEqual Operator = "gte"
	LessThan           Operator = "lt"
	LessThanOrEqual    Operator = "lte"
)

// Range operators
const (
	Between    Operator = "bt"
	NotBetween Operator = "nbt"
)

// Set operators
const (
	// use to check if a value is within a set of values
	// receives a list/array of values to compare against
	In Operator = "in"
	// use to check if a value is not within a set of values
	// receives a list/array of values to compare against
	NotIn Operator = "nin"
	// use to check if a set is a superset of another set
	// requires two sets/arrays to compare
	SuperSetOf Operator = "sset"
	// use to check if a set is not a superset of another set
	// requires two sets/arrays to compare
	// returns true if the first set does not contain all elements of the second set
	NotSuperSet Operator = "nsset"
)

// text operators
const (
	// use to check if a string includes a substring, the match is case sensitive
	Includes Operator = "inc"
	// use to check if a string does not include a substring, the match is case sensitive
	NotIncludes Operator = "ninc"
	// use to check if a string includes a substring, the match is case insensitive
	InsentiveIncludes Operator = "iinc"
	// use to check if a string does not include a substring, the match is case insensitive
	InsentiveNotIncludes Operator = "ininc"
)

// operatorInfo holds metadata about an operator
type operatorInfo struct {
	Category    Category
	Description string
}

// registry maps operators to their metadata
var registry = map[Operator]operatorInfo{
	// Equality
	Equal:    {CategoryEquality, "equals"},
	NotEqual: {CategoryEquality, "not equals"},

	// Numeric
	GreaterThan:        {CategoryNumeric, "greater than"},
	GreaterThanOrEqual: {CategoryNumeric, "greater than or equal"},
	LessThan:           {CategoryNumeric, "less than"},
	LessThanOrEqual:    {CategoryNumeric, "less than or equal"},

	// Range
	Between:    {CategoryRange, "between two values"},
	NotBetween: {CategoryRange, "not between two values"},

	// Set
	In:          {CategorySet, "in set of values"},
	NotIn:       {CategorySet, "not in set of values"},
	SuperSetOf:  {CategorySet, "is superset of another set"},
	NotSuperSet: {CategorySet, "is not superset of another set"},

	// Text
	Includes:             {CategoryText, "includes substring (case sensitive)"},
	NotIncludes:          {CategoryText, "does not include substring (case sensitive)"},
	InsentiveIncludes:    {CategoryText, "includes substring (case insensitive)"},
	InsentiveNotIncludes: {CategoryText, "does not include substring (case insensitive)"},
}

// IsValid checks if the operator is supported
func (o Operator) IsValid() bool {
	_, ok := registry[o]
	return ok
}

// Category returns the category of the operator
func (o Operator) Category() Category {
	if info, ok := registry[o]; ok {
		return info.Category
	}
	return ""
}

// Description returns the human-readable description of the operator
func (o Operator) Description() string {
	if info, ok := registry[o]; ok {
		return info.Description
	}
	return ""
}

// String returns the string representation of the operator
func (o Operator) String() string {
	return string(o)
}

// Parse converts a string to an Operator
func Parse(s string) (Operator, bool) {
	op := Operator(s)
	if op.IsValid() {
		return op, true
	}
	return "", false
}

// All returns all registered operators
func All() []Operator {
	ops := make([]Operator, 0, len(registry))
	for op := range registry {
		ops = append(ops, op)
	}
	return ops
}

// ByCategory returns all operators in a given category
func ByCategory(cat Category) []Operator {
	var ops []Operator
	for op, info := range registry {
		if info.Category == cat {
			ops = append(ops, op)
		}
	}
	return ops
}
