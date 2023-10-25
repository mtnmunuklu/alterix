package modifiers

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

func GetComparator(modifiers ...string) (ComparatorFunc, error) {
	return getComparator(Comparators, modifiers...)
}

func GetComparatorCaseSensitive(modifiers ...string) (ComparatorFunc, error) {
	return getComparator(ComparatorsCaseSensitive, modifiers...)
}

func getComparator(comparators map[string]Comparator, modifiers ...string) (ComparatorFunc, error) {
	if len(modifiers) == 0 {
		return baseComparator{}.Alters, nil
	}

	// A valid sequence of modifiers is ([ValueModifier]*)[Comparator]?
	// If a comparator is specified, it must be in the last position and cannot be succeeded by any other modifiers
	// If no comparator is specified, the default comparator is used
	var valueModifiers []ValueModifier
	var eventValueModifiers []ValueModifier
	var comparator Comparator
	for i, modifier := range modifiers {
		comparatorModifier := comparators[modifier]
		valueModifier := ValueModifiers[modifier]
		eventValueModifier := EventValueModifiers[modifier]
		switch {
		// Validate correctness
		case comparatorModifier == nil && valueModifier == nil && eventValueModifier == nil:
			return nil, fmt.Errorf("unknown modifier %s", modifier)
		case i < len(modifiers)-1 && comparators[modifier] != nil:
			return nil, fmt.Errorf("comparator modifier %s must be the last modifier", modifier)

		// Build up list of modifiers
		case valueModifier != nil:
			valueModifiers = append(valueModifiers, valueModifier)
		case eventValueModifier != nil:
			eventValueModifiers = append(eventValueModifiers, eventValueModifier)
		case comparatorModifier != nil:
			comparator = comparatorModifier
		}
	}
	if comparator == nil {
		comparator = baseComparator{}
	}

	return func(field, value any) (string, error) {
		var err error
		for _, modifier := range eventValueModifiers {
			value, err = modifier.Modify(value)
			if err != nil {
				return "", err
			}
		}
		for _, modifier := range valueModifiers {
			value, err = modifier.Modify(value)
			if err != nil {
				return "", err
			}
		}

		return comparator.Alters(field, value)
	}, nil
}

type Comparator interface {
	Alters(field any, value any) (string, error)
}

type ComparatorFunc func(field, value any) (string, error)

// ValueModifier modifies the expected value before it is passed to the comparator.
// For example, the `base64` modifier converts the expected value to base64.
type ValueModifier interface {
	Modify(value any) (any, error)
}

var Comparators = map[string]Comparator{
	"contains":   contains{},
	"endswith":   endswith{},
	"startswith": startswith{},
	"re":         re{},
	"cidr":       cidr{},
	"gt":         gt{},
	"gte":        gte{},
	"lt":         lt{},
	"lte":        lte{},
}

var ComparatorsCaseSensitive = map[string]Comparator{
	"contains":   containsCS{},
	"endswith":   endswithCS{},
	"startswith": startswithCS{},
	"re":         re{},
	"cidr":       cidr{},
	"gt":         gt{},
	"gte":        gte{},
	"lt":         lt{},
	"lte":        lte{},
}

var ValueModifiers = map[string]ValueModifier{
	"base64": b64{},
	"wide":   wide{},
}

// EventValueModifiers modify the value in the event before comparison (as opposed to ValueModifiers which modify the value in the rule)
var EventValueModifiers = map[string]ValueModifier{}

type baseComparator struct{}

func (baseComparator) Alters(field, value any) (string, error) {
	switch {
	case field == nil && value == "null":
		return "", nil
	default:
		// The Sigma spec defines that by default comparisons are case-insensitive
		return fmt.Sprintf("%v = '%v'", strings.ToLower(coerceString(field)), strings.ToLower(coerceString(value))), nil
	}
}

type contains struct{}

func (contains) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%%%v%%'", strings.ToLower(coerceString(field)), strings.ToLower(coerceString(value))), nil
}

type endswith struct{}

func (endswith) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%%%v'", strings.ToLower(coerceString(field)), strings.ToLower(coerceString(value))), nil
}

type startswith struct{}

func (startswith) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%v%%'", strings.ToLower(coerceString(field)), strings.ToLower(coerceString(value))), nil
}

type containsCS struct{}

func (containsCS) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%%%v%%'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

type endswithCS struct{}

func (endswithCS) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%%%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

type startswithCS struct{}

func (startswithCS) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%v%%'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

type re struct{}

func (re) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v re '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

type cidr struct{}

func (cidr) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v cidr '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

type gt struct{}

func (gt) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v > '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

type gte struct{}

func (gte) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v >= '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

type lt struct{}

func (lt) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v < '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

type lte struct{}

func (lte) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v <= '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

type b64 struct{}

func (b64) Modify(value any) (any, error) {
	return base64.StdEncoding.EncodeToString([]byte(coerceString(value))), nil
}

type wide struct{}

func (wide) Modify(value any) (any, error) {
	runes := utf16.Encode([]rune(coerceString(value)))
	bytes := make([]byte, 2*len(runes))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(bytes[i*2:], r)
	}
	return coerceString(bytes), nil
}

func coerceString(v interface{}) string {
	switch vv := v.(type) {
	case string:
		return vv
	case []byte:
		return string(vv)
	default:
		return fmt.Sprint(vv)
	}
}
