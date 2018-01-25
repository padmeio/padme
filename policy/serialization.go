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
func marshalOp(op Operator) (string, error) {
    var str string
    switch op {
    case AND: str = "AND"
    case OR: str = "OR"
    case NONE: str = "NONE"
    default:
	return "", fmt.Errorf("Invalid operator: '%v'. Valid values are AND, OR, NONE", op)
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
	return NONE, fmt.Errorf("Invalid operator: '%v'. Valid values are AND, OR, NONE", str)
    }
    return op, nil
}

/**
 * RuleSet serialization
 */
func (rs* RuleSet) MarshalJSON() ([]byte, error) {
    operator, err := marshalOp(rs.OOperator)
    if err != nil { return nil, err }

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

/**
 * Helper type that allows to partially deserialize a RuleSet so we can
 * use the standard JSON unmarshaler to deserialize the non-recursive objects.
 */
type PartialRuleSet struct {
    Op string		    `json:"op"`
    Rule *json.RawMessage   `json:"rule"`
    Left *PartialRuleSet    `json:"left"`
    Right *PartialRuleSet   `json:"right"`
}

func (rs* RuleSet) UnmarshalJSON(data []byte) (error) {
    raw := &PartialRuleSet{}
    if err := json.Unmarshal(data, raw); err != nil { return err }
    ruleset, err := unmarshalRuleSet(raw)
    if err == nil { *rs = *ruleset }
    return err
}

func unmarshalRuleSet(raw *PartialRuleSet) (*RuleSet, error) {
    if raw == nil { return nil, nil }
    var err error
    var op Operator
    var rule *Rule
    var left, right *RuleSet

    op, err = unmarshalOp(raw.Op)
    if err != nil { return nil, err }

    if raw.Rule != nil {
	rule = &Rule{}
	if err = json.Unmarshal(*raw.Rule, rule); err != nil {
	    return nil, fmt.Errorf("Cannot unmarshal rule: %v", string(*raw.Rule))
	}
    }

    left, err = unmarshalRuleSet(raw.Left)
    if err != nil { return nil, err }

    right, err = unmarshalRuleSet(raw.Right)
    if err != nil { return nil, err }

    return &RuleSet{OOperator: op, RRule: rule, LArg: left, RArg: right}, nil
}

/**
 * PolicyLine serialization
 */
func (pl *PolicyLine) MarshalJSON() ([]byte, error) {
    operator, err := marshalOp(pl.OOperator)
    if err != nil { return nil, err }

    // Use an alias type to avoid infinite recursion during serialization
    type Alias *PolicyLine
    return json.Marshal(&struct {
	Op string	`json:"op"`
	Policy *Policy	`json:policy,omitempty"`
	Left Alias	`json:"left,omitempty"`
	Right Alias	`json:"right,omitempty"`
    }{
	Op: operator,
	Policy: pl.PPolicy,
	Left: Alias(pl.LArg),
	Right: Alias(pl.RArg),
    })
}

/**
 * Helper type that allows to partially deserialize a PolicyLine so we can
 * use the standard JSON unmarshaler to deserialize the non-recursive objects.
 */
type PartialPolicyLine struct {
    Op string			`json:"op"`
    Policy *json.RawMessage	`json:"policy"`
    Left *PartialPolicyLine	`json:"left"`
    Right *PartialPolicyLine	`json:"right"`
}

func (pl *PolicyLine) UnmarshalJSON(data []byte) (error) {
    raw := &PartialPolicyLine{}
    if err := json.Unmarshal(data, raw); err != nil { return err }
    policyline, err := unmarshalPolicyLine(raw)
    if err == nil { *pl = *policyline }
    return err
}

func unmarshalPolicyLine(raw *PartialPolicyLine) (*PolicyLine, error) {
    if raw == nil { return nil, nil }
    var err error
    var op Operator
    var policy *Policy
    var left, right *PolicyLine

    op, err = unmarshalOp(raw.Op)
    if err != nil { return nil, err }

    if raw.Policy != nil {
	policy = &Policy{}
	if err = json.Unmarshal(*raw.Policy, policy); err != nil {
	    return nil, fmt.Errorf("Cannot unmarshal policy: %v", string(*raw.Policy))
	}
    }

    left, err = unmarshalPolicyLine(raw.Left)
    if err != nil { return nil, err }
    
    right, err = unmarshalPolicyLine(raw.Right)
    if err != nil { return nil, err }

    return &PolicyLine{OOperator: op, PPolicy: policy, LArg: left, RArg: right}, nil
}
