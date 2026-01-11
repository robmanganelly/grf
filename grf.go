// Package grf provides a query library for REST APIs that enables rich querying capabilities.
//
// It sits on top of standard REST APIs to allow clients to pass complex filters
// in a standardized way.
//
// # Usage
//
//	import "github.com/robmanganelly/grf"
//
//	// Define your filter schema
//	type UserFilters struct {
//	    Name   string  `grf:"name"`
//	    Age    float64 `grf:"age"`
//	    Status string  `grf:"status"`
//	}
//
//	// Parse query parameters
//	func handleUsers(w http.ResponseWriter, r *http.Request) {
//	    var query grf.Query[UserFilters]
//	    if err := grf.ParseQuery(r.URL.Query(), &query); err != nil {
//	        http.Error(w, err.Error(), http.StatusBadRequest)
//	        return
//	    }
//
//	    // Generate SQL WHERE clause
//	    result, err := grf.ToSQLWhere(query.Filters)
//	    if err != nil {
//	        http.Error(w, err.Error(), http.StatusInternalServerError)
//	        return
//	    }
//
//	    // Use result.Clause and result.Args in your query
//	    // e.g., "name = $1 AND age > $2", ["john", 25]
//	}
//
// # Query Format
//
// The query format uses explicit suffixes to indicate value types:
//
//	f.<field>.o    - operator (required)
//	f.<field>.v    - single value (for equality, numeric)
//	f.<field>.r.from, f.<field>.r.to - range values (for range operators)
//	f.<field>.vs   - multiple values (for set operators)
//	f.<field>.p    - pattern (for text operators)
//	f.<field>.g    - group (optional)
//
// # Examples
//
//	f.name.o=eq&f.name.v=john                              // equality
//	f.age.o=gt&f.age.v=25                                  // numeric
//	f.date.o=bt&f.date.r.from=100&f.date.r.to=200          // range
//	f.status.o=in&f.status.vs=active&f.status.vs=pending   // set
//	f.title.o=inc&f.title.p=hello                          // text pattern
//
// # Operators
//
// Equality: eq (equals), ne (not equals)
// Numeric: gt (>), gte (>=), lt (<), lte (<=)
// Range: bt (between), nbt (not between)
// Set: in, nin (not in), sset (superset), nsset (not superset)
// Text: inc (includes), ninc (not includes), iinc (case-insensitive includes), ininc (case-insensitive not includes)
package grf

import (
	"net/url"

	"github.com/robmanganelly/grf/internal/operators"
	"github.com/robmanganelly/grf/internal/parser"
)

// Re-export types from internal packages

// Query holds the parsed query result.
// The type parameter T defines the allowed filter fields via struct tags.
type Query[T any] = parser.Query[T]

// Filter is the interface all filter types implement
type Filter = parser.Filter

// FilterType discriminator for schema generation
type FilterType = parser.FilterType

// Filter type constants
const (
	FilterTypeEquality = parser.FilterTypeEquality
	FilterTypeNumeric  = parser.FilterTypeNumeric
	FilterTypeRange    = parser.FilterTypeRange
	FilterTypeSet      = parser.FilterTypeSet
	FilterTypeText     = parser.FilterTypeText
)

// Concrete filter types
type (
	EqualityFilter = parser.EqualityFilter
	NumericFilter  = parser.NumericFilter
	RangeFilter    = parser.RangeFilter
	SetFilter      = parser.SetFilter
	TextFilter     = parser.TextFilter
	RangeValue     = parser.RangeValue
)

// SQLWhereResult contains the WHERE clause and its arguments
type SQLWhereResult = parser.SQLWhereResult

// ParseError represents a parsing error with context
type ParseError = parser.ParseError

// Operator represents a filter operator
type Operator = operators.Operator

// Operator constants - Equality
const (
	OpEqual    = operators.Equal
	OpNotEqual = operators.NotEqual
)

// Operator constants - Numeric
const (
	OpGreaterThan        = operators.GreaterThan
	OpGreaterThanOrEqual = operators.GreaterThanOrEqual
	OpLessThan           = operators.LessThan
	OpLessThanOrEqual    = operators.LessThanOrEqual
)

// Operator constants - Range
const (
	OpBetween    = operators.Between
	OpNotBetween = operators.NotBetween
)

// Operator constants - Set
const (
	OpIn          = operators.In
	OpNotIn       = operators.NotIn
	OpSuperSetOf  = operators.SuperSetOf
	OpNotSuperSet = operators.NotSuperSet
)

// Operator constants - Text
const (
	OpIncludes               = operators.Includes
	OpNotIncludes            = operators.NotIncludes
	OpInsensitiveIncludes    = operators.InsentiveIncludes
	OpInsensitiveNotIncludes = operators.InsentiveNotIncludes
)

// Category represents the category of an operator
type Category = operators.Category

// Category constants
const (
	CategoryEquality = operators.CategoryEquality
	CategoryNumeric  = operators.CategoryNumeric
	CategoryRange    = operators.CategoryRange
	CategorySet      = operators.CategorySet
	CategoryText     = operators.CategoryText
)

// ParseQuery parses URL query parameters and populates the target Query.
// The type parameter T should be a struct that defines allowed filter fields
// via `grf` struct tags.
//
// Example:
//
//	type UserFilters struct {
//	    Name   string `grf:"name"`
//	    Age    int    `grf:"age"`
//	}
//
//	var query grf.Query[UserFilters]
//	err := grf.ParseQuery(r.URL.Query(), &query)
func ParseQuery[T any](params url.Values, target *Query[T]) error {
	return parser.ParseQuery(params, target)
}

// ToSQLWhere generates a SQL WHERE clause from filters.
// Uses field names directly as column names.
//
// Example:
//
//	result, err := grf.ToSQLWhere(query.Filters)
//	// result.Clause: "name = $1 AND age > $2"
//	// result.Args: ["john", 25]
func ToSQLWhere(filters []Filter) (*SQLWhereResult, error) {
	return parser.ToSQLWhere(filters)
}

// ToSQLWhereAlias generates a SQL WHERE clause from filters with field name mapping.
// The keymap maps filter field names to database column names.
// If a field is not in keymap, the field name is used directly.
//
// Example:
//
//	keymap := map[string]string{
//	    "name": "users.full_name",
//	    "age":  "users.age",
//	}
//	result, err := grf.ToSQLWhereAlias(query.Filters, keymap)
//	// result.Clause: "users.full_name = $1 AND users.age > $2"
//	// result.Args: ["john", 25]
func ToSQLWhereAlias(filters []Filter, keymap map[string]string) (*SQLWhereResult, error) {
	return parser.ToSQLWhereAlias(filters, keymap)
}

// ParseOperator converts a string to an Operator.
// Returns the operator and true if valid, or empty operator and false if invalid.
//
// Example:
//
//	op, ok := grf.ParseOperator("eq")
//	if ok {
//	    fmt.Println(op) // "eq"
//	}
func ParseOperator(s string) (Operator, bool) {
	return operators.Parse(s)
}

// AllOperators returns all registered operators.
func AllOperators() []Operator {
	return operators.All()
}

// OperatorsByCategory returns all operators in a given category.
//
// Example:
//
//	numericOps := grf.OperatorsByCategory(grf.CategoryNumeric)
//	// [gt, gte, lt, lte]
func OperatorsByCategory(cat Category) []Operator {
	return operators.ByCategory(cat)
}
