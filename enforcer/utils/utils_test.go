/*
Copyright 2018 Ignasi Barrera

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"reflect"
	"testing"

	"github.com/padmeio/padme/policy"
)

func TestNewResourceWhenEmpty(t *testing.T) {
	var rules []*policy.Rule
	if _, err := NewResource(rules, &policy.Credential{}); err == nil {
		t.Fatal("Expected method to fail when there are not input rules")
	}
}

func TestNewResourceWhenSingle(t *testing.T) {
	var rules = make([]*policy.Rule, 1)
	rules[0] = &policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=127.0.0.1"}
	res, err := NewResource(rules, &policy.Credential{})
	if err != nil {
		t.Fatal(err)
	}

	expected := &policy.RuleSet{OOperator: policy.NONE, RRule: rules[0]}
	if !reflect.DeepEqual(res.Name, expected) {
		t.Fatalf("Expected a resource with the given rule but found: %v", res.Name)
	}
}

func TestNewResourceMultiple(t *testing.T) {
	var rules = make([]*policy.Rule, 2)
	rules[0] = &policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=127.0.0.1"}
	rules[1] = &policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=10.0.0.2"}
	res, err := NewResource(rules, &policy.Credential{})
	if err != nil {
		t.Fatal(err)
	}

	expected := &policy.RuleSet{
		OOperator: policy.AND,
		LArg:      &policy.RuleSet{OOperator: policy.NONE, RRule: rules[0]},
		RArg:      &policy.RuleSet{OOperator: policy.NONE, RRule: rules[1]},
	}
	if !reflect.DeepEqual(res.Name, expected) {
		t.Fatalf("Expected a resource with the given rules but found: %v", res.Name)
	}
}

func TestLocalAddresses(t *testing.T) {
	// At least we should find the loopback address
	addrs, err := LocalAddresses()
	if err != nil {
		t.Fatal(err)
	}

	loopbackPresent := false
	for _, addr := range addrs {
		if addr == "127.0.0.1" {
			loopbackPresent = true
			break
		}
	}

	if !loopbackPresent {
		t.Fatalf("Expected to have at least the loopback address, but found: %v", addrs)
	}
}

func TestAddressesToResourceWhenEmpty(t *testing.T) {
	var addrs []string
	if _, err := AddressesToResource(addrs, &policy.Credential{}); err == nil {
		t.Fatal("Expected method to fail when there are not input addresses")
	}
}

func TestAddressesToResourceWhenSingle(t *testing.T) {
	res, err := AddressesToResource([]string{"127.0.0.1"}, &policy.Credential{})
	if err != nil {
		t.Fatal(err)
	}
	rule := &policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=127.0.0.1"}
	expected := &policy.RuleSet{OOperator: policy.NONE, RRule: rule}
	if !reflect.DeepEqual(res.Name, expected) {
		t.Fatalf("Expected a resource with the given rules but found: %v", res.Name)
	}
}

func TestAddressesToResourceMultiple(t *testing.T) {
	res, err := AddressesToResource([]string{"127.0.0.1", "10.0.0.2"}, &policy.Credential{})
	if err != nil {
		t.Fatal(err)
	}

	rule1 := &policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=127.0.0.1"}
	rule2 := &policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=10.0.0.2"}
	expected := &policy.RuleSet{
		OOperator: policy.OR,
		LArg:      &policy.RuleSet{OOperator: policy.NONE, RRule: rule1},
		RArg:      &policy.RuleSet{OOperator: policy.NONE, RRule: rule2},
	}
	if !reflect.DeepEqual(res.Name, expected) {
		t.Fatalf("Expected a resource with the given rules but found: %v", res.Name)
	}
}
