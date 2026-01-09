package parser

import (
	"fmt"
	"sort"
	"strings"

	"github.com/robmanganelly/gql/internal/operators"
)

// SQLWhereResult contains the WHERE clause and its arguments
type SQLWhereResult struct {
	Clause string // The WHERE clause (without "WHERE" prefix)
	Args   []any  // The positional arguments for the clause
}

// ToSQLWhere generates a SQL WHERE clause from filters.
// Uses field names directly as column names.
//
// Example:
//
//	result, err := parser.ToSQLWhere(query.Filters)
//	// result.Clause: "name = $1 AND age > $2"
//	// result.Args: ["john", 25]
func ToSQLWhere(filters []Filter) (*SQLWhereResult, error) {
	return ToSQLWhereAlias(filters, nil)
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
//	result, err := parser.ToSQLWhereAlias(query.Filters, keymap)
//	// result.Clause: "users.full_name = $1 AND users.age > $2"
//	// result.Args: ["john", 25]
func ToSQLWhereAlias(filters []Filter, keymap map[string]string) (*SQLWhereResult, error) {
	if len(filters) == 0 {
		return &SQLWhereResult{Clause: "", Args: nil}, nil
	}

	// Group filters by their group key
	groups := make(map[string][]Filter)
	for _, f := range filters {
		group := f.GetGroup()
		if group == "" {
			group = "_default"
		}
		groups[group] = append(groups[group], f)
	}

	// Sort group keys for deterministic output
	groupKeys := make([]string, 0, len(groups))
	for k := range groups {
		groupKeys = append(groupKeys, k)
	}
	sort.Strings(groupKeys)

	var args []any
	argIndex := 1
	var groupClauses []string

	for _, groupKey := range groupKeys {
		groupFilters := groups[groupKey]
		var filterClauses []string

		for _, f := range groupFilters {
			clause, filterArgs, newIndex, err := filterToSQL(f, keymap, argIndex)
			if err != nil {
				return nil, err
			}
			filterClauses = append(filterClauses, clause)
			args = append(args, filterArgs...)
			argIndex = newIndex
		}

		// Filters within same group are combined with AND
		if len(filterClauses) > 0 {
			groupClause := strings.Join(filterClauses, " AND ")
			if len(filterClauses) > 1 {
				groupClause = "(" + groupClause + ")"
			}
			groupClauses = append(groupClauses, groupClause)
		}
	}

	// Different groups are combined with OR
	var finalClause string
	if len(groupClauses) == 1 {
		finalClause = groupClauses[0]
	} else {
		finalClause = strings.Join(groupClauses, " OR ")
	}

	return &SQLWhereResult{
		Clause: finalClause,
		Args:   args,
	}, nil
}

// filterToSQL converts a single filter to SQL clause and returns the clause, args, and next arg index
func filterToSQL(f Filter, keymap map[string]string, argIndex int) (string, []any, int, error) {
	field := resolveFieldName(f.GetField(), keymap)

	switch filter := f.(type) {
	case EqualityFilter:
		return equalityToSQL(filter, field, argIndex)
	case NumericFilter:
		return numericToSQL(filter, field, argIndex)
	case RangeFilter:
		return rangeToSQL(filter, field, argIndex)
	case SetFilter:
		return setToSQL(filter, field, argIndex)
	case TextFilter:
		return textToSQL(filter, field, argIndex)
	default:
		return "", nil, argIndex, &ParseError{
			Field:   f.GetField(),
			Message: fmt.Sprintf("unsupported filter type: %T", f),
		}
	}
}

// resolveFieldName returns the mapped column name or the field name if not mapped
func resolveFieldName(field string, keymap map[string]string) string {
	if keymap == nil {
		return field
	}
	if mapped, ok := keymap[field]; ok {
		return mapped
	}
	return field
}

// sqlOperatorMap maps operators to their SQL equivalents
var sqlOperatorMap = map[operators.Operator]string{
	operators.Equal:              "=",
	operators.NotEqual:           "!=",
	operators.GreaterThan:        ">",
	operators.GreaterThanOrEqual: ">=",
	operators.LessThan:           "<",
	operators.LessThanOrEqual:    "<=",
}

// equalityToSQL handles eq, ne operators
func equalityToSQL(f EqualityFilter, field string, argIndex int) (string, []any, int, error) {
	// Handle NULL comparisons
	if f.Value == nil {
		switch f.Operator {
		case operators.Equal:
			return fmt.Sprintf("%s IS NULL", field), nil, argIndex, nil
		case operators.NotEqual:
			return fmt.Sprintf("%s IS NOT NULL", field), nil, argIndex, nil
		}
	}

	sqlOp, ok := sqlOperatorMap[f.Operator]
	if !ok {
		return "", nil, argIndex, &ParseError{
			Field:   f.Field,
			Message: fmt.Sprintf("unsupported equality operator: %s", f.Operator),
		}
	}

	clause := fmt.Sprintf("%s %s $%d", field, sqlOp, argIndex)
	return clause, []any{f.Value}, argIndex + 1, nil
}

// numericToSQL handles gt, gte, lt, lte operators
func numericToSQL(f NumericFilter, field string, argIndex int) (string, []any, int, error) {
	sqlOp, ok := sqlOperatorMap[f.Operator]
	if !ok {
		return "", nil, argIndex, &ParseError{
			Field:   f.Field,
			Message: fmt.Sprintf("unsupported numeric operator: %s", f.Operator),
		}
	}

	clause := fmt.Sprintf("%s %s $%d", field, sqlOp, argIndex)
	return clause, []any{f.Value}, argIndex + 1, nil
}

// rangeToSQL handles bt, nbt operators
func rangeToSQL(f RangeFilter, field string, argIndex int) (string, []any, int, error) {
	var clause string
	switch f.Operator {
	case operators.Between:
		clause = fmt.Sprintf("%s BETWEEN $%d AND $%d", field, argIndex, argIndex+1)
	case operators.NotBetween:
		clause = fmt.Sprintf("%s NOT BETWEEN $%d AND $%d", field, argIndex, argIndex+1)
	default:
		return "", nil, argIndex, &ParseError{
			Field:   f.Field,
			Message: fmt.Sprintf("unsupported range operator: %s", f.Operator),
		}
	}

	return clause, []any{f.Value.From, f.Value.To}, argIndex + 2, nil
}

// setToSQL handles in, nin, sset, nsset operators
func setToSQL(f SetFilter, field string, argIndex int) (string, []any, int, error) {
	if len(f.Values) == 0 {
		return "", nil, argIndex, &ParseError{
			Field:   f.Field,
			Message: "set filter requires at least one value",
		}
	}

	// Build placeholders
	placeholders := make([]string, len(f.Values))
	for i := range f.Values {
		placeholders[i] = fmt.Sprintf("$%d", argIndex+i)
	}
	placeholderStr := strings.Join(placeholders, ", ")

	var clause string
	switch f.Operator {
	case operators.In:
		clause = fmt.Sprintf("%s IN (%s)", field, placeholderStr)
	case operators.NotIn:
		clause = fmt.Sprintf("%s NOT IN (%s)", field, placeholderStr)
	case operators.SuperSetOf:
		// For superset: field contains all values in the set
		// This assumes field is an array column (PostgreSQL syntax)
		clause = fmt.Sprintf("%s @> ARRAY[%s]", field, placeholderStr)
	case operators.NotSuperSet:
		// For not superset: field does not contain all values
		clause = fmt.Sprintf("NOT (%s @> ARRAY[%s])", field, placeholderStr)
	default:
		return "", nil, argIndex, &ParseError{
			Field:   f.Field,
			Message: fmt.Sprintf("unsupported set operator: %s", f.Operator),
		}
	}

	return clause, f.Values, argIndex + len(f.Values), nil
}

// textToSQL handles inc, ninc, iinc, ininc operators
func textToSQL(f TextFilter, field string, argIndex int) (string, []any, int, error) {
	var clause string
	var pattern string

	switch f.Operator {
	case operators.Includes:
		// Case sensitive LIKE
		pattern = "%" + escapeSQL(f.Pattern) + "%"
		clause = fmt.Sprintf("%s LIKE $%d", field, argIndex)
	case operators.NotIncludes:
		// Case sensitive NOT LIKE
		pattern = "%" + escapeSQL(f.Pattern) + "%"
		clause = fmt.Sprintf("%s NOT LIKE $%d", field, argIndex)
	case operators.InsentiveIncludes:
		// Case insensitive ILIKE (PostgreSQL) or LOWER() for others
		pattern = "%" + escapeSQL(f.Pattern) + "%"
		clause = fmt.Sprintf("%s ILIKE $%d", field, argIndex)
	case operators.InsentiveNotIncludes:
		// Case insensitive NOT ILIKE
		pattern = "%" + escapeSQL(f.Pattern) + "%"
		clause = fmt.Sprintf("%s NOT ILIKE $%d", field, argIndex)
	default:
		return "", nil, argIndex, &ParseError{
			Field:   f.Field,
			Message: fmt.Sprintf("unsupported text operator: %s", f.Operator),
		}
	}

	return clause, []any{pattern}, argIndex + 1, nil
}

// escapeSQL escapes special SQL LIKE characters in the pattern
func escapeSQL(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	// this is not meant to prevent SQL injection, only to escape LIKE wildcards
	// injection is prevented by using parameterized queries
	return s
}
