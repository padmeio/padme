/**
 * Copyright 2018 Ignasi Barrera
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
    "encoding/base64"
    "encoding/json"
    "fmt"
)

// marshalOp serializes an Operator
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

// unmarshalOp deserializes an operator
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

// Helper type that allows to partially deserialize a RuleSet so we can
// use the standard JSON unmarshaler to deserialize the non-recursive objects.
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

// unmarshalRuleSet unmarshals a RuleSet recursively
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
	    return nil, err
	}
    }

    left, err = unmarshalRuleSet(raw.Left)
    if err != nil { return nil, err }

    right, err = unmarshalRuleSet(raw.Right)
    if err != nil { return nil, err }

    return &RuleSet{OOperator: op, RRule: rule, LArg: left, RArg: right}, nil
}

/**
 * Content encoding
 */

// Helper struct to Base64 encode the blob contents when serializing
type PlainContents struct {
    PluginId string	    `json:"plugin_id"`
    StrBlob string	    `json:"blob"`
}

func (c *Contents) MarshalJSON() ([]byte, error) {
    encoded := base64.StdEncoding.EncodeToString(c.Blob)
    return json.Marshal(&PlainContents {
	PluginId: c.PluginId,
	StrBlob: encoded,
    })
}

func (c *Contents) UnmarshalJSON(data []byte) error {
    plainContents := PlainContents{}
    if err := json.Unmarshal(data, &plainContents); err != nil { return err }

    contents := Contents{}
    blob, err := base64.StdEncoding.DecodeString(plainContents.StrBlob)
    if err != nil { return err }
    contents.PluginId = plainContents.PluginId
    contents.Blob = blob

    *c = contents
    return nil
}

/**
 * PolicyLine serialization
 */

func (pl *PolicyLine) MarshalJSON() ([]byte, error) {
    operator, err := marshalOp(pl.OOperator)
    if err != nil { return nil, err }

    // Use an alias type to avoid infinite recursion during serialization
    type Alias *PolicyLine
    return json.Marshal(&map[string]struct {
	Op string	`json:"op"`
	Policy *Policy	`json:"policy,omitempty"`
	Left Alias	`json:"left,omitempty"`
	Right Alias	`json:"right,omitempty"`
    }{
	"policy_line": {
	    Op: operator,
	    Policy: pl.PPolicy,
	    Left: Alias(pl.LArg),
	    Right: Alias(pl.RArg),
	},
    })
}

// Helper type that allows to partially deserialize a PolicyLine so we can
// use the standard JSON unmarshaler to deserialize the non-recursive objects.
// PolicyLine objects are wrapped in a "policy_line" tag for better readability
// and to disambiguate the types when unmarshaling a PolicyBase type.
//
// Unlike RuleSets, we wrap this object because the generated JSON is easierto understand
// this way. RuleSets are nested inside a Resource (and a "rules" tag), so there is no need
// for an additional nesting level there.
type PartialPolicyLine struct {
    Op string				    `json:"op"`
    Policy *json.RawMessage		    `json:"policy"`
    Left map[string]*PartialPolicyLine	    `json:"left"`
    Right map[string]*PartialPolicyLine	    `json:"right"`
}

// Wrapper type to properly wrap and unwrap PolicyLine objects in a "policy_line" tag
type WrappedPolicyLine map[string]json.RawMessage

func (pl *PolicyLine) UnmarshalJSON(data []byte) (error) {
    // First unwrap the object from the "policy_line" tag
    var wrapper WrappedPolicyLine
    if err := json.Unmarshal(data, &wrapper); err != nil { return err }
    rawline, ok := wrapper["policy_line"];
    if !ok { return nil } // No PolicyLine present; just return
    // Once unwrapped, deserialize normally
    raw := &PartialPolicyLine{}
    if err := json.Unmarshal(rawline, raw); err != nil { return err }
    policyline, err := unmarshalPolicyLine(raw)
    if err == nil { *pl = *policyline }
    return err
}

// unmarshalPolicyLine unmarshals an already unwrapped PolicyLine object
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
	    return nil, err
	}
    }

    // Unwrap and deserialize recursively

    if unwrappedLeft, ok := raw.Left["policy_line"]; ok {
        left, err = unmarshalPolicyLine(unwrappedLeft)
	if err != nil { return nil, err }
    }

    if unwrappedRight, ok := raw.Right["policy_line"]; ok {
        right, err = unmarshalPolicyLine(unwrappedRight)
        if err != nil { return nil, err }
    }

    return &PolicyLine{OOperator: op, PPolicy: policy, LArg: left, RArg: right}, nil
}

/**
 * PolicyBundle serialization
 */

func (pb *PolicyBundle) UnmarshalJSON(data []byte) error {
    // We need to manually deserialize the PolicyBundle becasuse the Policies
    // list can hold different types of elements. We need to manually inspect each
    // one to properly determine its type and unmarshal accordingly.
    var raw map[string]json.RawMessage
    if err := json.Unmarshal(data, &raw); err != nil { return err }

    bundle := PolicyBundle{}

    var format_version, policy_version int64
    if err := json.Unmarshal(raw["format_version"], &format_version); err != nil { return err }
    bundle.FormatVersion = uint64(format_version)
    if err := json.Unmarshal(raw["policy_version"], &policy_version); err != nil { return err }
    bundle.PolicyVersion = uint64(policy_version)

    if err := json.Unmarshal(raw["description"], &bundle.Description); err != nil { return err }

    var rawpolicies []json.RawMessage
    if err := json.Unmarshal(raw["policies"], &rawpolicies); err != nil { return err }

    // To resolve the right type of the underlying PolicyBase object, we first try
    // to deserialize it as a PolicyLine. Since it is wrapped in a "policy_line" tag
    // we can use that as a hint to determine the type of the object.
    var modified bool
    policies := []PolicyBase{}
    for _, policybase := range rawpolicies {
	policies, modified = readPolicyLine(policybase, policies)
	// If the PolicyBase was not a PolicyLine, try to deserialize as a Policy
	if !modified {
	   policies, _ = readPolicy(policybase, policies)
	}
    }
    bundle.Policies = policies

    *pb = bundle
    return nil
}

func readPolicy(policybase json.RawMessage, policies []PolicyBase) ([]PolicyBase, bool) {
    policy := Policy{}
    modified := false
    if err := json.Unmarshal(policybase, &policy); err == nil {
	policies = append(policies, &policy)
	modified = true
    }
    return policies, modified
}

func readPolicyLine(policybase json.RawMessage, policies []PolicyBase) ([]PolicyBase, bool) {
    var wrapper WrappedPolicyLine
    modified := false
    // Check if it is an object wrapped in a "polocy_line" tag
    if err := json.Unmarshal(policybase, &wrapper); err == nil {
	if _, ok := wrapper["policy_line"]; ok {
	    line := PolicyLine{}
	    // If it is wrapped, then deserialize it
	    // FIXME: Note that we are deserializing again the whole object. This is because
	    // the PolicyLine unmarshaler expects a wrapped element. We need to find a way to
	    // do this better, as the "policybase" object has already been deserialised before, 
	    // but we lost the wrapper in the process
	    if err := json.Unmarshal(policybase, &line); err == nil {
		policies = append(policies, &line)
		modified = true
	    }
	}
    }
    return policies, modified
}

