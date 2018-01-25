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
    "testing"
)

func assertEquals(t *testing.T, actual interface{}, expected interface{}) {
    if actual != expected {
        t.Errorf("Expected %v but got: %v", expected, actual)
    }
}

func assertRuleSet(t *testing.T, actual *RuleSet, expected *RuleSet) {
    assertEquals(t, actual.OOperator, expected.OOperator)

    assertEquals(t, actual.RRule == nil, expected.RRule == nil)
    if actual.RRule != nil && expected.RRule != nil {
        assertEquals(t, *(actual.RRule), *(expected.RRule))
    }

    assertEquals(t, actual.LArg == nil, expected.LArg == nil)
    if actual.RRule != nil && expected.RRule != nil {
	assertRuleSet(t, actual.LArg, expected.LArg)
    }

    assertEquals(t, actual.RArg == nil, expected.RArg == nil)
    if actual.RRule != nil && expected.RRule != nil {
	assertRuleSet(t, actual.RArg, expected.RArg)
    }
}

func TestInvalidOperator(t *testing.T) {
    invalid := RuleSet{OOperator: 15}
    _, err := json.Marshal(&invalid)
    if err == nil {
	t.Errorf("Expected operator %v to produce an InvalidOperatorError", invalid.OOperator)
    } else {
	jsonError, _ := err.(*json.MarshalerError)
	switch jsonError.Err.(type) {
	case InvalidOperatorError:
	default:
	    t.Errorf("Expected operator %v to produce an InvalidOperatorError but got: %T", invalid.OOperator, err)
	}
    }
}

var jsonRuleSet = "{\"op\":\"OR\"," +
		    "\"left\":{\"op\":\"AND\"," +
			"\"left\":{\"op\":\"NONE\",\"rule\":{\"layer\":\"l1\",\"layer_type\":\"t1\",\"pattern\":\"p1\"}}," +
			"\"right\":{\"op\":\"NONE\",\"rule\":{\"layer\":\"l2\",\"layer_type\":\"t2\",\"pattern\":\"p2\"}}}," +
		    "\"right\":{\"op\":\"NONE\",\"rule\":{\"layer\":\"l3\",\"layer_type\":\"t3\",\"pattern\":\"p3\"}}}"

var rs1 = RuleSet{OOperator: NONE, RRule: &Rule{Layer: "l1", LType: "t1", Pattern: "p1"}}
var rs2 = RuleSet{OOperator: NONE, RRule: &Rule{Layer: "l2", LType: "t2", Pattern: "p2"}}
var rs3 = RuleSet{OOperator: NONE, RRule: &Rule{Layer: "l3", LType: "t3", Pattern: "p3"}}
var rsAnd = RuleSet{OOperator: AND, LArg: &rs1, RArg: &rs2}
var rsOr = RuleSet{OOperator: OR, LArg: &rsAnd, RArg: &rs3}

func TestRuleSetSerialization(t *testing.T) {
    serialized, err := json.Marshal(&rsOr)
    if err != nil {
	t.Errorf("Unable to serialize RuleSet: %v", err)
    }
    assertEquals(t, string(serialized), jsonRuleSet)
}

func TestDeserializeMissingOpertor(t *testing.T) {
    rs := RuleSet{}
    err := json.Unmarshal([]byte("{}"), &rs)
    if err == nil {
	t.Errorf("Expected deserialization to fail when operator is missing")
    }
    assertEquals(t, err.Error(), "Missing operator!")
}

func TestRuleSetDeserialization(t *testing.T) {
    rs := RuleSet{}
    if err := json.Unmarshal([]byte(jsonRuleSet), &rs); err != nil {
	t.Errorf("Unable to deserialize RuleSet: %v", err)
    }
    assertRuleSet(t, &rs, &rsOr)
}

