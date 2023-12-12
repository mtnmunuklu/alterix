package modifiers

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// any is an empty interface to represent any type.
type any interface{}

// ValueModifier is an interface for modifying the expected value before it is passed to the comparator.
type ValueModifier interface {
	Modify(value any) (any, error)
}

// ValueModifierWithParameter is an interface for modifying the expected value before it is passed to the comparator,
// and it can also take a parameter.
type ValueModifierWithParameter interface {
	ModifyWithParameter(value any, parameter string) (any, error)
}

// ValueModifiers is a map of value modifier names to ValueModifier implementations.
var ValueModifiers = map[string]ValueModifier{
	"nocase":     &nocase{},
	"ascii":      &ascii{},
	"wide":       &wide{},
	"xor":        &xor{},
	"base64":     &b64{},
	"base64wide": &b64wide{},
}

// ValueModifiersWithParameter is a map of value modifier names to ValueModifierWithParameter implementations.
var ValueModifiersWithParameter = map[string]ValueModifierWithParameter{
	"xor":        &xor{},
	"base64":     &b64{},
	"base64wide": &b64wide{},
}

// GetComparator returns a ComparatorFunc based on the provided modifiers.
func GetComparator(modifiers ...string) (ComparatorFunc, error) {
	return getComparator(Comparators, modifiers...)
}

// getComparator builds a ComparatorFunc based on the provided comparators and modifiers.
func getComparator(comparators map[string]Comparator, modifiers ...string) (ComparatorFunc, error) {
	if len(modifiers) == 0 {
		return baseComparator{}.Alters, nil
	}

	var valueModifiers []ValueModifier
	var valueModifiersWithParam []ValueModifierWithParameter
	var comparator Comparator

	for i, modifier := range modifiers {
		comparatorModifier := comparators[modifier]
		valueModifier, valueModifierWithParameter, parameter := extractModifier(modifier)

		switch {
		case comparatorModifier == nil && valueModifier == nil && valueModifierWithParameter == nil:
			return nil, fmt.Errorf("unknown modifier %s", modifier)
		case i < len(modifiers)-1 && comparators[modifier] != nil:
			return nil, fmt.Errorf("comparator modifier %s must be the last modifier", modifier)
		case valueModifier != nil:
			valueModifiers = append(valueModifiers, valueModifier)
		case valueModifierWithParameter != nil:
			adaptedModifier := adaptModifierFuncWithParameter(valueModifierWithParameter.ModifyWithParameter, parameter)
			valueModifiersWithParam = append(valueModifiersWithParam, adaptedModifier)
		case comparatorModifier != nil:
			comparator = comparatorModifier
		}
	}

	if comparator == nil {
		comparator = baseComparator{}
	}

	return func(field, value any) (string, error) {
		var err error
		for _, modifier := range valueModifiers {
			value, err = modifier.Modify(value)
			if err != nil {
				return "", err
			}
		}
		for _, modifier := range valueModifiersWithParam {
			value, err = modifier.ModifyWithParameter(value, "")
			if err != nil {
				return "", err
			}
		}
		return comparator.Alters(field, value)
	}, nil
}

// extractModifier extracts the modifier name and parameter from a string.
func extractModifier(modifier string) (ValueModifier, ValueModifierWithParameter, string) {
	if strings.Contains(modifier, "(") && strings.Contains(modifier, ")") {
		modifierName := strings.Split(modifier, "(")[0]
		parameterString := strings.TrimSuffix(strings.TrimPrefix(modifier, modifierName+"("), ")")
		parameter := parameterString

		if valueModifierWithParameter, ok := ValueModifiersWithParameter[modifierName]; ok {
			return nil, valueModifierWithParameter, parameter
		} else {
			return nil, nil, ""
		}
	}

	if valueModifier, ok := ValueModifiers[modifier]; ok {
		return valueModifier, nil, ""
	}

	return nil, nil, ""
}

// Comparator is an interface for comparison operations.
type Comparator interface {
	Alters(field any, value any) (string, error)
}

// ComparatorFunc is a function signature for comparators.
type ComparatorFunc func(field, value any) (string, error)

// ModifierFunc is a function signature for modifying the expected value.
type ModifierFunc func(value any) (any, error)

// ModifierFuncWithParameter is a function signature for modifying the expected value with a parameter.
type ModifierFuncWithParameter func(value any, parameter string) (any, error)

// Comparators is a map of comparator names to Comparator implementations.
var Comparators = map[string]Comparator{
	"contains":    contains{},
	"icontains":   icontains{},
	"endswith":    endswith{},
	"iendswith":   iendswith{},
	"startswith":  startswith{},
	"istartswith": istartswith{},
	"gt":          gt{},
	"ge":          ge{},
	"lt":          lt{},
	"le":          le{},
	"fullword":    fullword{},
	"eq":          eq{},
	"iequals":     ieq{},
	"neq":         neq{},
}

// baseComparator is a default comparator implementation.
type baseComparator struct{}

func (baseComparator) Alters(field, value any) (string, error) {
	switch {
	case field == nil && value == "null":
		return "", nil
	default:
		// The Sigma spec defines that by default comparisons are case-insensitive
		return fmt.Sprintf("%v like '%%%v%%'", strings.ToLower(coerceString(field)), coerceString(value)), nil
	}
}

// contains is a comparator implementation for the 'contains' operation.
type contains struct{}

func (contains) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%%%v%%'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

// icontains is a comparator implementation for the 'icontains' operation.
type icontains struct{}

func (icontains) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%%%v%%'", strings.ToLower(coerceString(field)), strings.ToLower(coerceString(value))), nil
}

// endswith is a comparator implementation for the 'endswith' operation.
type endswith struct{}

func (endswith) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%%%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

// iendswith is a comparator implementation for the 'iendswith' operation.
type iendswith struct{}

func (iendswith) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%%%v'", strings.ToLower(coerceString(field)), strings.ToLower(coerceString(value))), nil
}

// startswith is a comparator implementation for the 'startswith' operation.
type startswith struct{}

func (startswith) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%v%%'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

// istartswith is a comparator implementation for the 'istartswith' operation.
type istartswith struct{}

func (istartswith) Alters(field, value any) (string, error) {
	return fmt.Sprintf("%v like '%v%%'", strings.ToLower(coerceString(field)), strings.ToLower(coerceString(value))), nil
}

// gt is a comparator implementation for the 'gt' operation.
type gt struct{}

func (gt) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v > '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

// ge is a comparator implementation for the 'ge' operation.
type ge struct{}

func (ge) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v >= '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

// lt is a comparator implementation for the 'lt' operation.
type lt struct{}

func (lt) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v < '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

// le is a comparator implementation for the 'le' operation.
type le struct{}

func (le) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v <= '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

// fullword is a comparator implementation for the 'fullword' operation.
type fullword struct{}

func (fullword) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v = '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

// eq is a comparator implementation for the 'eq' operation.
type eq struct{}

func (eq) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v = '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

// ieq is a comparator implementation for the 'ieq' operation.
type ieq struct{}

func (ieq) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v = '%v'", strings.ToLower(coerceString(field)), strings.ToLower(coerceString(value))), nil
}

// neq is a comparator implementation for the 'neq' operation.
type neq struct{}

func (neq) Alters(field any, value any) (string, error) {
	return fmt.Sprintf("%v != '%v'", strings.ToLower(coerceString(field)), coerceString(value)), nil
}

// nocase is a value modifier implementation for the 'nocase' operation.
type nocase struct{}

func (nocase) Modify(value any) (any, error) {
	return strings.ToLower(coerceString(value)), nil
}

// ascii is a value modifier implementation for the 'ascii' operation.
type ascii struct{}

func (ascii) Modify(value any) (any, error) {
	return coerceString(value), nil
}

// wide is a value modifier implementation for the 'wide' operation.
type wide struct{}

func (wide) Modify(value any) (any, error) {
	runes := utf16.Encode([]rune(coerceString(value)))
	bytes := make([]byte, 2*len(runes))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(bytes[i*2:], r)
	}
	return coerceString(bytes), nil
}

// xor is a value modifier implementation for the 'xor' operation.
type xor struct{}

func (xor) Modify(value any) (any, error) {
	// Simple XOR with a key of 0x01
	key := byte(0x01)
	result := make([]byte, len(coerceString(value)))
	for i := 0; i < len(coerceString(value)); i++ {
		result[i] = coerceString(value)[i] ^ key
	}
	return coerceString(result), nil
}

func (xor) ModifyWithParameter(value any, parameter string) (any, error) {
	// Implement this method if needed
	return nil, fmt.Errorf("ModifyWithParameter not implemented for 'xor'")
}

// b64 is a value modifier implementation for the 'base64' operation.
type b64 struct{}

func (b64) Modify(value any) (any, error) {
	encoded := base64.StdEncoding.EncodeToString([]byte(coerceString(value)))
	return encoded, nil
}

func (b64) ModifyWithParameter(value any, parameter string) (any, error) {
	// Implement this method if needed
	return nil, fmt.Errorf("ModifyWithParameter not implemented for 'base64'")
}

// b64wide is a value modifier implementation for the 'base64wide' operation.
type b64wide struct{}

func (b64wide) Modify(value any) (any, error) {
	runes := utf16.Encode([]rune(coerceString(value)))
	bytes := make([]byte, 2*len(runes))
	for i, r := range runes {
		binary.LittleEndian.PutUint16(bytes[i*2:], r)
	}
	encoded := base64.StdEncoding.EncodeToString(bytes)
	return encoded, nil
}

func (b64wide) ModifyWithParameter(value any, parameter string) (any, error) {
	// Implement this method if needed
	return nil, fmt.Errorf("ModifyWithParameter not implemented for 'base64wide'")
}

// coerceString converts the given value to a string.
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

// adaptModifierFuncWithParameter adapts a ModifierFuncWithParameter to a ValueModifierWithParameter.
func adaptModifierFuncWithParameter(modifyWithParamFunc ModifierFuncWithParameter, parameter string) ValueModifierWithParameter {
	return &modifierFuncAdapterWithParameter{modifyWithParamFunc, parameter}
}

// modifierFuncAdapterWithParameter adapts a ModifierFuncWithParameter to a ValueModifierWithParameter.
type modifierFuncAdapterWithParameter struct {
	modifyWithParamFunc ModifierFuncWithParameter
	parameter           string
}

func (m *modifierFuncAdapterWithParameter) Modify(value any) (any, error) {
	return m.modifyWithParamFunc(value, m.parameter)
}

// ModifyWithParameter implements ValueModifierWithParameter interface.
func (m *modifierFuncAdapterWithParameter) ModifyWithParameter(value any, parameter string) (any, error) {
	if m.modifyWithParamFunc != nil {
		return m.modifyWithParamFunc(value, parameter)
	}
	return nil, fmt.Errorf("ModifyWithParameter not implemented for the underlying modifier function")
}
