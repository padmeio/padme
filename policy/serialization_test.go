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
    "io/ioutil"
    "testing"
    "time"
)

func assertEquals(t *testing.T, actual interface{}, expected interface{}) {
    if actual != expected {
        t.Errorf("Expected %v but got: %v", expected, actual)
    }
}

func TestInvalidOperator(t *testing.T) {
    invalid := RuleSet{OOperator: 15}
    _, err := json.Marshal(&invalid)
    if err == nil {
	t.Errorf("Expected operator %v to produce an error", invalid.OOperator)
    }
    jsonError, _ := err.(*json.MarshalerError)
    assertEquals(t, jsonError.Err.Error(), "Invalid operator: '15'. Valid values are AND, OR, NONE")
}

func TestDeserializeMissingOpertor(t *testing.T) {
    pl := PolicyLine{}
    err := json.Unmarshal([]byte("{}"), &pl)
    if err == nil {
	t.Errorf("Expected deserialization to fail when operator is missing")
    }
    assertEquals(t, err.Error(), "Invalid operator: ''. Valid values are AND, OR, NONE")
}

var c1 = Credential{ Name: "n1", Value: "v1" }
var forever =  Duration{ time.Date(0, 1, 1, 0,0,0,0, time.UTC), time.Date(3000, 1,1, 0,0,0,0, time.UTC) }
var everywhere = Location { "everywhere" }

var tcp80Name = makeIPRule("10.0.0.1").And(makeTCPRule("80")).And(makeServiceRule("/home"))
var tcp443Name = makeIPRule("10.0.0.1").And(makeTCPRule("443")).And(makeServiceRule("/home"))

var tcp80Resource = Resource{ Name: tcp80Name, IdentifiedBy: &c1 }
var tcp443Resource = Resource{ Name: tcp443Name, IdentifiedBy: &c1 }

// This is tautological, but we're testing the policy line matcher not the deeper policy logic
var tcp80Policy = makePolicy(tcp80Resource, &tcp80Resource, nil,  forever, everywhere)
var tcp443Policy = makePolicy(tcp443Resource, &tcp443Resource, nil,  forever, everywhere)

var tcp80PolicyLine = PolicyLine{ OOperator: NONE, PPolicy: tcp80Policy }
var tcp443PolicyLine = PolicyLine{ OOperator: NONE, PPolicy: tcp443Policy }
var tcp80or443PolicyLine = PolicyLine{ OOperator: OR, LArg: &tcp80PolicyLine, RArg: &tcp443PolicyLine }

func TestPolicySerialization(t *testing.T) {
    var jsonPolicy, err = ioutil.ReadFile("./test_policy.json")
    if err != nil {
        panic("Unable to read policy json file")
    }

    serialized, err := json.Marshal(&tcp80or443PolicyLine)
    if err != nil {
	t.Errorf("Unable to serialize PolicyLine: %v", err)
    }

    deserialized := &PolicyLine{}
    if err = json.Unmarshal(jsonPolicy, deserialized); err != nil {
	t.Errorf("Unable to deserialize PolicyLine: %v", err)
    }

    // Serialize again (remove pretty formatting) and compare both versions
    var result []byte
    result, err = json.Marshal(deserialized)
    if err != nil {
	t.Errorf("Unable to serialize PolicyLine after deserialization: %v", err)
    }

    assertEquals(t, string(serialized), string(result))
}

