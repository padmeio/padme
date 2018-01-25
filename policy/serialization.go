/**
 * Copyright 2017 Kamil Pawlowski, Ignasi Barrera
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package policy

import (
    "encoding/json"
    "fmt"
)

/**
 * Operator serialization
 */
type InvalidOperatorError Operator

func (oe InvalidOperatorError) Error() string {
    return fmt.Sprintf("Invalid operator: %v. Valid values are AND, OR, NONE", oe)
}

func marshalOp(op Operator) (string, error) {
    var str string
    switch op {
    case AND: str = "AND"
    case OR: str = "OR"
    case NONE: str = "NONE"
    default:
	return "", InvalidOperatorError(op)
    }
    return str, nil
}

func unmarshalOp(str string) (Operator, error) {
    var op Operator
    switch str {
    case "AND": op = AND
    case "OR": op = OR
    case "NONE": op = NONE
    default:
	return NONE, InvalidOperatorError(op)
    }
    return op, nil
}

/**
 * RuleSet serialization
 */
func (rs* RuleSet) MarshalJSON() ([]byte, error) {
    operator, err := marshalOp(rs.OOperator)
    if err != nil {
	return nil, err
    }
    // Use an alias type to avoid infinite recursion during serialization
    type Alias *RuleSet
    return json.Marshal(&struct {
	Op string	`json:"op"`
	Rule* Rule	`json:"rule,omitempty"`
	Left Alias	`json:"left,omitempty"`
	Right Alias	`json:"right,omitempty"`
    }{
	Op: operator,
	Rule: rs.RRule,
	Left: Alias(rs.LArg),
	Right: Alias(rs.RArg),
    })
}

func (rs* RuleSet) UnmarshalJSON(data []byte) (error) {
    // We cannot unmarshal directl to recursive structs using pointers, so let's
    // unmarshal the struct manually
    var raw map[string]interface{}
    if err := json.Unmarshal(data, &raw); err != nil {
	return err
    }
    ruleset, err := unmarshalRuleSet(raw)
    if err == nil {
        *rs = *ruleset
    }
    return err
}

func unmarshalRuleSet(raw map[string]interface{}) (*RuleSet, error) {
    rawop, hasop := raw["op"]
    rawrule, hasrule := raw["rule"]
    rawleft, hasleft := raw["left"]
    rawright, hasright := raw["right"]

    var err error
    var op Operator
    var rule *Rule
    var left, right *RuleSet

    if !hasop {
	// FIXME: Use NONE instead of failing? 
	return nil, fmt.Errorf("Missing operator!")
    }

    op, err = unmarshalOp(rawop.(string))
    if err != nil {
	return nil, err
    }

    if hasrule {
	r := rawrule.(map[string]interface{})
	rule = &Rule{Layer: fmt.Sprintf("%v", r["layer"]),
		    LType: fmt.Sprintf("%v", r["layer_type"]),
		    Pattern: fmt.Sprintf("%v", r["pattern"])}
    }

    if hasleft {
	left, err = unmarshalRuleSet(rawleft.(map[string]interface{}))
	if err != nil {
	    return nil, err
	}
    }

    if hasright {
	right, err = unmarshalRuleSet(rawright.(map[string]interface{}))
	if err != nil {
	    return nil, err
	}
    }

    return &RuleSet{OOperator: op, RRule: rule, LArg: left, RArg: right}, nil
}
