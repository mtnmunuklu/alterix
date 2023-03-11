package evaluator

import (
	"context"
	"fmt"

	"Alterix/sigma"
)

func (rule RuleEvaluator) evaluateAggregationExpression(ctx context.Context, conditionIndex int, aggregation sigma.AggregationExpr) (string, error) {
	var aggregationResult string
	switch agg := aggregation.(type) {
	case sigma.Near:
		return aggregationResult, fmt.Errorf("near isn't supported yet")

	case sigma.Comparison:
		aggregationResult, err := rule.evaluateAggregationFunc(ctx, conditionIndex, agg.Func)
		if err != nil {
			return aggregationResult, err
		}

		return aggregationResult + " " + string(agg.Op) + " " + fmt.Sprintf("%d", int(agg.Threshold)), nil

	default:
		return aggregationResult, fmt.Errorf("unknown aggregation expression")
	}
}

func (rule RuleEvaluator) evaluateAggregationFunc(ctx context.Context, conditionIndex int, aggregation sigma.AggregationFunc) (string, error) {
	var result string
	switch agg := aggregation.(type) {
	case sigma.Count:
		if agg.Field == "" {
			if agg.GroupedBy != "" {
				result = "select " + agg.GroupedBy
			}
			result += ", count(*)|group having count(*)"
			return result, nil
		} else {
			if len(rule.fieldmappings[agg.Field]) != 0 {
				agg.Field = rule.fieldmappings[agg.Field][0]
			}
			result = "select " + agg.Field
			if agg.GroupedBy != "" {
				if len(rule.fieldmappings[agg.GroupedBy]) != 0 {
					agg.GroupedBy = rule.fieldmappings[agg.GroupedBy][0]
				}
				result += ", " + agg.GroupedBy
			}
			result += ", count(*)|group having count(*)"
			return result, nil
		}

	case sigma.Average:
		if len(rule.fieldmappings[agg.Field]) != 0 {
			agg.Field = rule.fieldmappings[agg.Field][0]
		}
		result = "select " + agg.Field
		if agg.GroupedBy != "" {
			if len(rule.fieldmappings[agg.GroupedBy]) != 0 {
				agg.GroupedBy = rule.fieldmappings[agg.GroupedBy][0]
			}
			result += ", " + agg.GroupedBy
		}
		result += ", avg(" + agg.Field + ")|group having avg(" + agg.Field + ")"
		return result, nil

	case sigma.Sum:
		if len(rule.fieldmappings[agg.Field]) != 0 {
			agg.Field = rule.fieldmappings[agg.Field][0]
		}
		result = "select " + agg.Field
		if agg.GroupedBy != "" {
			if len(rule.fieldmappings[agg.GroupedBy]) != 0 {
				agg.GroupedBy = rule.fieldmappings[agg.GroupedBy][0]
			}
			result += ", " + agg.GroupedBy
		}
		result += ", sum(" + agg.Field + ")|group having sum(" + agg.Field + ")"
		return result, nil

	case sigma.Min:
		if len(rule.fieldmappings[agg.Field]) != 0 {
			agg.Field = rule.fieldmappings[agg.Field][0]
		}
		result = "select " + agg.Field
		if agg.GroupedBy != "" {
			if len(rule.fieldmappings[agg.GroupedBy]) != 0 {
				agg.GroupedBy = rule.fieldmappings[agg.GroupedBy][0]
			}
			result += ", " + agg.GroupedBy
		}
		result += ", min(" + agg.Field + ")|group having min(" + agg.Field + ")"
		return result, nil

	case sigma.Max:
		if len(rule.fieldmappings[agg.Field]) != 0 {
			agg.Field = rule.fieldmappings[agg.Field][0]
		}
		result = "select " + agg.Field
		if agg.GroupedBy != "" {
			if len(rule.fieldmappings[agg.GroupedBy]) != 0 {
				agg.GroupedBy = rule.fieldmappings[agg.GroupedBy][0]
			}
			result += ", " + agg.GroupedBy
		}
		result += ", max(" + agg.Field + ")|group having max(" + agg.Field + ")"
		return result, nil

	default:
		return result, fmt.Errorf("unsupported aggregation function")
	}
}
