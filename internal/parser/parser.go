// Package parser provides query string parsing functionality.
//
// # Usage
//
//	import "github.com/robmanganelly/grf/internal/parser"
//
//	// Define your filter schema
//	type UserFilters struct {
//	    Name   string  `grf:"name"`
//	    Age    float64 `grf:"age"`
//	    Status string  `grf:"status"`
//	}
//
//	// Parse query parameters (idiomatic pointer pattern)
//	var query parser.Query[UserFilters]
//	err := parser.ParseQuery(r.URL.Query(), &query)
//	if err != nil {
//	    // handle error
//	}
//
//	// Access parsed filters with type safety
//	for _, f := range query.Filters {
//	    switch filter := f.(type) {
//	    case parser.NumericFilter:
//	        fmt.Printf("Numeric: %s %s %f\n", filter.Field, filter.Operator, filter.Value)
//	    case parser.EqualityFilter:
//	        fmt.Printf("Equality: %s %s %v\n", filter.Field, filter.Operator, filter.Value)
//	    case parser.RangeFilter:
//	        fmt.Printf("Range: %s %s [%f, %f]\n", filter.Field, filter.Operator, filter.Value.From, filter.Value.To)
//	    case parser.SetFilter:
//	        fmt.Printf("Set: %s %s %v\n", filter.Field, filter.Operator, filter.Values)
//	    }
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
// Examples:
//
//	f.name.o=eq&f.name.v=john                           // equality
//	f.age.o=gt&f.age.v=25                               // numeric
//	f.date.o=bt&f.date.r.from=100&f.date.r.to=200      // range
//	f.status.o=in&f.status.vs=active&f.status.vs=pending // set
//	f.title.o=inc&f.title.p=hello                       // text pattern
package parser

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/robmanganelly/grf/internal/operators"
)

// FilterType discriminator for schema generation
type FilterType string

const (
	FilterTypeEquality FilterType = "equality"
	FilterTypeNumeric  FilterType = "numeric"
	FilterTypeRange    FilterType = "range"
	FilterTypeSet      FilterType = "set"
	FilterTypeText     FilterType = "text"
)

// Filter is the interface all filter types implement
type Filter interface {
	GetType() FilterType
	GetField() string
	GetGroup() string
	GetOperator() operators.Operator
	Validate() error
	sealed() // prevents external implementations
}

// baseFilter contains common fields (embedded in all filter types)
type baseFilter struct {
	Field string `json:"field"`
	Group string `json:"group,omitempty"`
}

func (b baseFilter) GetField() string { return b.Field }
func (b baseFilter) GetGroup() string { return b.Group }

// EqualityFilter for eq, ne operators - accepts any comparable value
type EqualityFilter struct {
	baseFilter
	Type     FilterType         `json:"type"`     // always "equality"
	Operator operators.Operator `json:"operator"` // eq, ne
	Value    any                `json:"value"`    // string, number, bool, null
}

func (f EqualityFilter) GetType() FilterType             { return FilterTypeEquality }
func (f EqualityFilter) GetOperator() operators.Operator { return f.Operator }
func (f EqualityFilter) sealed()                         {}
func (f EqualityFilter) Validate() error {
	if f.Operator != operators.Equal && f.Operator != operators.NotEqual {
		return &ParseError{Field: f.Field, Message: "equality filter requires eq or ne operator"}
	}
	return nil
}

// NumericFilter for gt, gte, lt, lte operators
type NumericFilter struct {
	baseFilter
	Type     FilterType         `json:"type"`     // always "numeric"
	Operator operators.Operator `json:"operator"` // gt, gte, lt, lte
	Value    float64            `json:"value"`
}

func (f NumericFilter) GetType() FilterType             { return FilterTypeNumeric }
func (f NumericFilter) GetOperator() operators.Operator { return f.Operator }
func (f NumericFilter) sealed()                         {}
func (f NumericFilter) Validate() error {
	switch f.Operator {
	case operators.GreaterThan, operators.GreaterThanOrEqual,
		operators.LessThan, operators.LessThanOrEqual:
		return nil
	default:
		return &ParseError{Field: f.Field, Message: "numeric filter requires gt, gte, lt, or lte operator"}
	}
}

// RangeValue represents inclusive bounds
type RangeValue struct {
	From float64 `json:"from"`
	To   float64 `json:"to"`
}

// RangeFilter for bt, nbt operators
type RangeFilter struct {
	baseFilter
	Type     FilterType         `json:"type"`     // always "range"
	Operator operators.Operator `json:"operator"` // bt, nbt
	Value    RangeValue         `json:"value"`
}

func (f RangeFilter) GetType() FilterType             { return FilterTypeRange }
func (f RangeFilter) GetOperator() operators.Operator { return f.Operator }
func (f RangeFilter) sealed()                         {}
func (f RangeFilter) Validate() error {
	if f.Operator != operators.Between && f.Operator != operators.NotBetween {
		return &ParseError{Field: f.Field, Message: "range filter requires bt or nbt operator"}
	}
	if f.Value.From > f.Value.To {
		return &ParseError{Field: f.Field, Message: "range 'from' must be <= 'to'"}
	}
	return nil
}

// SetFilter for in, nin, sset, nsset operators
type SetFilter struct {
	baseFilter
	Type     FilterType         `json:"type"`     // always "set"
	Operator operators.Operator `json:"operator"` // in, nin, sset, nsset
	Values   []any              `json:"values"`
}

func (f SetFilter) GetType() FilterType             { return FilterTypeSet }
func (f SetFilter) GetOperator() operators.Operator { return f.Operator }
func (f SetFilter) sealed()                         {}
func (f SetFilter) Validate() error {
	switch f.Operator {
	case operators.In, operators.NotIn, operators.SuperSetOf, operators.NotSuperSet:
		// valid
	default:
		return &ParseError{Field: f.Field, Message: "set filter requires in, nin, sset, or nsset operator"}
	}
	if len(f.Values) == 0 {
		return &ParseError{Field: f.Field, Message: "set filter requires at least one value"}
	}
	return nil
}

// TextFilter for inc, ninc, iinc, ininc operators
type TextFilter struct {
	baseFilter
	Type     FilterType         `json:"type"`     // always "text"
	Operator operators.Operator `json:"operator"` // inc, ninc, iinc, ininc
	Pattern  string             `json:"pattern"`
}

func (f TextFilter) GetType() FilterType             { return FilterTypeText }
func (f TextFilter) GetOperator() operators.Operator { return f.Operator }
func (f TextFilter) sealed()                         {}
func (f TextFilter) Validate() error {
	switch f.Operator {
	case operators.Includes, operators.NotIncludes,
		operators.InsentiveIncludes, operators.InsentiveNotIncludes:
		// valid
	default:
		return &ParseError{Field: f.Field, Message: "text filter requires inc, ninc, iinc, or ininc operator"}
	}
	if f.Pattern == "" {
		return &ParseError{Field: f.Field, Message: "text filter requires a non-empty pattern"}
	}
	return nil
}

// Query holds the parsed query result.
// The type parameter T defines the allowed filter fields via struct tags.
type Query[T any] struct {
	Filters     []Filter // Interface type - use type switch to access concrete types
	FilterCount int      // from fc parameter, used to detect URL truncation
	validated   bool     // internal flag to track if query was validated
}

// ParseError represents a parsing error with context
type ParseError struct {
	Field   string
	Message string
}

func (e *ParseError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("parse error on field '%s': %s", e.Field, e.Message)
	}
	return fmt.Sprintf("parse error: %s", e.Message)
}

// rawFilter is used internally during parsing before type resolution
type rawFilter struct {
	field     string
	operator  operators.Operator
	value     string   // single value (v)
	values    []string // multiple values (vs)
	rangeFrom string   // range from (r.from)
	rangeTo   string   // range to (r.to)
	pattern   string   // text pattern (p)
	group     string
	// track which value types were provided
	hasValue   bool
	hasValues  bool
	hasRange   bool
	hasPattern bool
}

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
//	var query parser.Query[UserFilters]
//	err := parser.ParseQuery(params, &query)
func ParseQuery[T any](params url.Values, target *Query[T]) error {
	if target == nil {
		return &ParseError{Message: "target cannot be nil"}
	}

	// Get allowed fields from the type parameter's struct tags
	allowedFields, err := extractAllowedFields[T]()
	if err != nil {
		return err
	}

	// Initialize
	target.Filters = make([]Filter, 0)
	target.validated = false

	// Parse fc (filter count) if present
	if fc := params.Get("fc"); fc != "" {
		count, err := strconv.Atoi(fc)
		if err != nil {
			return &ParseError{Field: "fc", Message: "must be a valid integer"}
		}
		target.FilterCount = count
	}

	// Track parsed filters by field
	parsedFilters := make(map[string]*rawFilter)

	for key, values := range params {
		if !strings.HasPrefix(key, "f.") {
			continue
		}

		// Remove "f." prefix and split
		parts := strings.Split(strings.TrimPrefix(key, "f."), ".")
		if len(parts) < 2 {
			continue
		}

		field := parts[0]
		suffix := parts[1]

		if _, ok := allowedFields[field]; !ok {
			return &ParseError{
				Field:   field,
				Message: fmt.Sprintf("field '%s' is not allowed", field),
			}
		}

		if _, exists := parsedFilters[field]; !exists {
			parsedFilters[field] = &rawFilter{field: field}
		}
		raw := parsedFilters[field]

		switch suffix {
		case "o": // operator
			if len(values) == 0 {
				continue
			}
			op, ok := operators.Parse(values[0])
			if !ok {
				return &ParseError{
					Field:   field,
					Message: fmt.Sprintf("invalid operator '%s'", values[0]),
				}
			}
			raw.operator = op

		case "v": // single value (equality, numeric)
			if len(values) > 0 {
				raw.value = values[0]
				raw.hasValue = true
			}

		case "vs": // multiple values (set)
			raw.values = append(raw.values, values...)
			raw.hasValues = true

		case "r": // range (r.from, r.to)
			if len(parts) >= 3 {
				switch parts[2] {
				case "from":
					if len(values) > 0 {
						raw.rangeFrom = values[0]
						raw.hasRange = true
					}
				case "to":
					if len(values) > 0 {
						raw.rangeTo = values[0]
						raw.hasRange = true
					}
				}
			}

		case "p": // pattern (text)
			if len(values) > 0 {
				raw.pattern = values[0]
				raw.hasPattern = true
			}

		case "g": // group
			if len(values) > 0 {
				raw.group = values[0]
			}
		}
	}

	// Convert raw filters to typed filters
	for field, raw := range parsedFilters {
		if raw.operator == "" {
			return &ParseError{Field: field, Message: "missing operator"}
		}

		filter, err := buildTypedFilter(raw, allowedFields[field])
		if err != nil {
			return err
		}

		if err := filter.Validate(); err != nil {
			return err
		}

		target.Filters = append(target.Filters, filter)
	}

	// Validate filter count
	if target.FilterCount > 0 && len(target.Filters) != target.FilterCount {
		return &ParseError{
			Message: fmt.Sprintf("expected %d filters, got %d (possible URL truncation)",
				target.FilterCount, len(target.Filters)),
		}
	}

	target.validated = true
	return nil
}

// buildTypedFilter creates the appropriate filter type based on operator category
// and validates that the correct value type was provided
func buildTypedFilter(raw *rawFilter, fieldType reflect.Type) (Filter, error) {
	base := baseFilter{Field: raw.field, Group: raw.group}
	category := raw.operator.Category()

	switch category {
	case operators.CategoryEquality:
		// Equality requires single value (v)
		if !raw.hasValue {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "equality operator requires 'v' (single value), use f.<field>.v=<value>",
			}
		}
		if raw.hasRange {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "equality operator does not accept range values (r.from/r.to)",
			}
		}
		if raw.hasValues {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "equality operator does not accept multiple values (vs), use 'v' for single value",
			}
		}
		if raw.hasPattern {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "equality operator does not accept pattern (p), use 'v' for single value",
			}
		}

		// Try to parse as number, otherwise keep as string
		var value any = raw.value
		if f, err := strconv.ParseFloat(raw.value, 64); err == nil {
			value = f
		} else if raw.value == "true" {
			value = true
		} else if raw.value == "false" {
			value = false
		}

		return EqualityFilter{
			baseFilter: base,
			Type:       FilterTypeEquality,
			Operator:   raw.operator,
			Value:      value,
		}, nil

	case operators.CategoryNumeric:
		// Numeric requires single value (v)
		if !raw.hasValue {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "numeric operator requires 'v' (single value), use f.<field>.v=<number>",
			}
		}
		if raw.hasRange {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "numeric operator does not accept range values (r.from/r.to), use 'v' for single value",
			}
		}
		if raw.hasValues {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "numeric operator does not accept multiple values (vs), use 'v' for single value",
			}
		}
		if raw.hasPattern {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "numeric operator does not accept pattern (p), use 'v' for single value",
			}
		}

		val, err := strconv.ParseFloat(raw.value, 64)
		if err != nil {
			return nil, &ParseError{Field: raw.field, Message: "numeric filter value must be a number"}
		}
		return NumericFilter{
			baseFilter: base,
			Type:       FilterTypeNumeric,
			Operator:   raw.operator,
			Value:      val,
		}, nil

	case operators.CategoryRange:
		// Range requires r.from and r.to
		if !raw.hasRange {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "range operator requires 'r.from' and 'r.to', use f.<field>.r.from=<value>&f.<field>.r.to=<value>",
			}
		}
		if raw.hasValue {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "range operator does not accept single value (v), use 'r.from' and 'r.to'",
			}
		}
		if raw.hasValues {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "range operator does not accept multiple values (vs), use 'r.from' and 'r.to'",
			}
		}
		if raw.hasPattern {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "range operator does not accept pattern (p), use 'r.from' and 'r.to'",
			}
		}
		if raw.rangeFrom == "" {
			return nil, &ParseError{Field: raw.field, Message: "range filter requires 'r.from' value"}
		}
		if raw.rangeTo == "" {
			return nil, &ParseError{Field: raw.field, Message: "range filter requires 'r.to' value"}
		}

		from, err := strconv.ParseFloat(raw.rangeFrom, 64)
		if err != nil {
			return nil, &ParseError{Field: raw.field, Message: "range 'r.from' must be a number"}
		}
		to, err := strconv.ParseFloat(raw.rangeTo, 64)
		if err != nil {
			return nil, &ParseError{Field: raw.field, Message: "range 'r.to' must be a number"}
		}
		return RangeFilter{
			baseFilter: base,
			Type:       FilterTypeRange,
			Operator:   raw.operator,
			Value:      RangeValue{From: from, To: to},
		}, nil

	case operators.CategorySet:
		// Set requires multiple values (vs)
		if !raw.hasValues {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "set operator requires 'vs' (values), use f.<field>.vs=<value1>&f.<field>.vs=<value2>",
			}
		}
		if raw.hasValue {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "set operator does not accept single value (v), use 'vs' for multiple values",
			}
		}
		if raw.hasRange {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "set operator does not accept range values (r.from/r.to), use 'vs' for multiple values",
			}
		}
		if raw.hasPattern {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "set operator does not accept pattern (p), use 'vs' for multiple values",
			}
		}

		values := make([]any, len(raw.values))
		for i, v := range raw.values {
			values[i] = v
		}
		return SetFilter{
			baseFilter: base,
			Type:       FilterTypeSet,
			Operator:   raw.operator,
			Values:     values,
		}, nil

	case operators.CategoryText:
		// Text requires pattern (p)
		if !raw.hasPattern {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "text operator requires 'p' (pattern), use f.<field>.p=<pattern>",
			}
		}
		if raw.hasValue {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "text operator does not accept single value (v), use 'p' for pattern",
			}
		}
		if raw.hasValues {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "text operator does not accept multiple values (vs), use 'p' for pattern",
			}
		}
		if raw.hasRange {
			return nil, &ParseError{
				Field:   raw.field,
				Message: "text operator does not accept range values (r.from/r.to), use 'p' for pattern",
			}
		}

		return TextFilter{
			baseFilter: base,
			Type:       FilterTypeText,
			Operator:   raw.operator,
			Pattern:    raw.pattern,
		}, nil

	default:
		return nil, &ParseError{Field: raw.field, Message: fmt.Sprintf("unsupported operator category: %s", category)}
	}
}

// extractAllowedFields extracts field names from the type parameter's struct tags
func extractAllowedFields[T any]() (map[string]reflect.Type, error) {
	var zero T
	t := reflect.TypeOf(zero)

	// Handle pointer types
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return nil, &ParseError{Message: "type parameter must be a struct"}
	}

	fields := make(map[string]reflect.Type)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("grf")
		if tag == "" || tag == "-" {
			continue
		}
		// Handle tag options (e.g., `grf:"name,omitempty"`)
		tagName := strings.Split(tag, ",")[0]
		fields[tagName] = field.Type
	}

	return fields, nil
}
