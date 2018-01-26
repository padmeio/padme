/**
 * Copyright 2017 Kamil Pawlowski
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

/**
 * PADME Policy Definiton (v2) basic tests
 */
package policy

import (
	"encoding/json"
	"testing"
	"time"
)

// rules for testing fun
var r1 = Rule{Layer: "l1", LType: "t1", Pattern: "p"}
var r2 = Rule{Layer: "l1", LType: "t2", Pattern: "p"}
var r3 = Rule{Layer: "l2", LType: "t1", Pattern: "p"}
var r4 = Rule{Layer: "l1", LType: "t1", Pattern: "q"}
var r5 = Rule{Layer: "l1", LType: "t1", Pattern: "p"}
var r6 = Rule{Layer: "l2", LType: "t1", Pattern: "q"}

var rsNone1 = RuleSet{OOperator: NONE, RRule: &r1, LArg: nil, RArg: nil}
var rsNone2 = RuleSet{OOperator: NONE, RRule: &r2, LArg: nil, RArg: nil}
var rsNone3 = RuleSet{OOperator: NONE, RRule: &r3, LArg: nil, RArg: nil}
var rsNone4 = RuleSet{OOperator: NONE, RRule: &r4, LArg: nil, RArg: nil}
var rsNone5 = RuleSet{OOperator: NONE, RRule: &r5, LArg: nil, RArg: nil}
var rsNone6 = RuleSet{OOperator: NONE, RRule: &r6, LArg: nil, RArg: nil}
var rsAnd1 = RuleSet{OOperator: AND, RRule: nil, LArg: &rsNone1, RArg: &rsNone2}
var rsAnd2 = RuleSet{OOperator: AND, RRule: nil, LArg: &rsNone1, RArg: &rsNone1}
var rsAnd3 = RuleSet{OOperator: AND, RRule: nil, LArg: &rsNone3, RArg: &rsNone1}
var rsAnd4 = RuleSet{OOperator: AND, RRule: nil, LArg: &rsNone4, RArg: &rsNone1}
var rsOr1 = RuleSet{OOperator: OR, RRule: nil, LArg: &rsNone1, RArg: &rsNone2}
var rsOr2 = RuleSet{OOperator: OR, RRule: nil, LArg: &rsNone1, RArg: &rsNone1}
var rsOr3 = RuleSet{OOperator: OR, RRule: nil, LArg: &rsNone3, RArg: &rsNone1}
var rsOr4 = RuleSet{OOperator: OR, RRule: nil, LArg: &rsNone3, RArg: &rsNone6}

func expect(t *testing.T, s string, eAccept bool, eMatch bool, accept bool, match bool) {
	if eAccept != accept || eMatch != match {
		t.Errorf("%s accept a: (e)%v/%v m (e)%v/%v", s, eAccept, accept, eMatch, match)
	}
}

/**
 * return a network/ip Layer rule for a given source address
 */
func makeIPRule(srcIP string) *RuleSet {
	var rule = Rule{Layer: "network", LType: "ip", Pattern: "srcIp " + srcIP}
	var ruleSet = RuleSet{OOperator: NONE, RRule: &rule, LArg: nil, RArg: nil}
	return &ruleSet
}

func makeTCPRule(destPort string) *RuleSet {
	var rule = Rule{Layer: "network", LType: "tcp", Pattern: "destPort " + destPort}
	var ruleSet = RuleSet{OOperator: NONE, RRule: &rule, LArg: nil, RArg: nil}
	return &ruleSet
}

func makeUDPRule(destPort string) *RuleSet {
	var rule = Rule{Layer: "network", LType: "udp", Pattern: "destPort " + destPort}
	var ruleSet = RuleSet{OOperator: NONE, RRule: &rule, LArg: nil, RArg: nil}
	return &ruleSet
}

func makeServiceRule(service string) *RuleSet {
	var rule = Rule{Layer: "service", LType: "www", Pattern: "service " + service}
	var ruleSet = RuleSet{OOperator: NONE, RRule: &rule, LArg: nil, RArg: nil}
	return &ruleSet
}

func makePolicy(target Resource, allowed *Resource, disallowed *Resource, timeline Duration, location Location) *Policy {
	// Avoid lists with nil elements
	allow := []*Resource{}
	forbid := []*Resource{}
	if allowed != nil {
		allow = append(allow, allowed)
	}
	if disallowed != nil {
		forbid = append(forbid, disallowed)
	}

	var p = Policy{
		FormatVersion: 0,
		PolicyVersion: 0,
		Description:   "",
		Target:        target,
		Allowed:       allow,
		Disallowed:    forbid,
		Timeline:      timeline,
		Rate:          0,
		LLocation:     location,
		CContents:     nil,
		Signature:     "",
	}
	return &p
}

func addPolicyContents(policy *Policy, contents ...*Contents) {
	for _, c := range contents {
		policy.CContents = append(policy.CContents, c)
	}
}

func TestRuleMatch(t *testing.T) {
	accept, match := r1.Match(&r2)
	expect(t, "r1 should not accept or match r2", false, false, accept, match)

	accept, match = r1.Match(&r3)
	expect(t, "r1 should not accept or match r3", false, false, accept, match)

	accept, match = r1.Match(&r4)
	expect(t, "r1 should accept but not match r4", true, false, accept, match)

	accept, match = r1.Match(&r5)
	expect(t, "r1 should accept and match r5", true, true, accept, match)
}

func TestRuleSetNoneRuleMatch(t *testing.T) {
	accept, match := rsNone1.Match_r(&r2)
	expect(t, "rsNone1 should not accept or match r2", false, false, accept, match)

	accept, match = rsNone1.Match_r(&r4)
	expect(t, "rsNone1 should accept but not match r4", true, false, accept, match)

	accept, match = rsNone1.Match_r(&r5)
	expect(t, "rsNone1 should accept and match r5", true, true, accept, match)
}

func TestRuleSetAndRuleMatch(t *testing.T) {
	accept, match := rsAnd1.Match_r(&r1)
	expect(t, "rsAnd1 should accept and match r1", true, true, accept, match)

	accept, match = rsAnd1.Match_r(&r2)
	expect(t, "rsAnd1 should accept and match r2", true, true, accept, match)

	accept, match = rsAnd1.Match_r(&r3)
	expect(t, "rsAnd1 should not accept nor match r3", false, false, accept, match)

	accept, match = rsAnd2.Match_r(&r3)
	expect(t, "rsAnd2 should not accept nor match r3", false, false, accept, match)

	accept, match = rsAnd2.Match_r(&r5)
	expect(t, "rsAnd2 should accept and match  r5", true, true, accept, match)
}

func TestRuleSetOrRuleMatch(t *testing.T) {
	accept, match := rsOr2.Match_r(&r2)
	expect(t, "rsOr2 should not accept nor match r2", false, false, accept, match)

	accept, match = rsOr1.Match_r(&r4)
	expect(t, "rsOr1 should accept but not match r4", true, false, accept, match)

	accept, match = rsOr1.Match_r(&r5)
	expect(t, "rsOr1 should accept and match r5", true, true, accept, match)

	accept, match = rsOr3.Match_r(&r6)
	expect(t, "rsOr3 should accept but not match r6", true, false, accept, match)

	accept, match = rsOr3.Match_r(&r3)
	expect(t, "rsOr1 should accept and match r3", true, true, accept, match)
}

func TestRuleSetRuleSetMatch(t *testing.T) {
	//here None is in the target rulesset
	accept, match := rsNone1.Match_rs(&rsNone2)
	expect(t, "rsNone1 should neither accept nor match rsNone2", false, false, accept, match)

	accept, match = rsNone1.Match_rs(&rsNone4)
	expect(t, "rsNone1 should accept but not match rsNone4", true, false, accept, match)

	accept, match = rsNone1.Match_rs(&rsNone5)
	expect(t, "rsNone1 should accept and match rsNone5", true, true, accept, match)

	//rsAnd1 -> none1 && none2 -> l1/t1/p && l1/t2/p
	//rsAnd3 -> none1 && none3 -> l2/t1/p && l1/t1/p
	accept, match = rsAnd1.Match_rs(&rsAnd3)
	expect(t, "rsAnd1 niether accepts nor matches rsAnd2", false, false, accept, match)

	accept, match = rsAnd3.Match_rs(&rsAnd1)
	expect(t, "rsAnd3 niether accepts nor matches rsAnd1", false, false, accept, match)

	accept, match = rsAnd1.Match_rs(&rsAnd1)
	expect(t, "rsAnd1 accepts and matches rsAnd1", true, true, accept, match)

	accept, match = rsAnd4.Match_rs(&rsAnd2)
	expect(t, "rsAnd4 accepts but does not match rsAnd2", true, false, accept, match)

	accept, match = rsAnd2.Match_rs(&rsAnd4)
	expect(t, "rsAnd2 accepts but does not match rsAnd4", true, false, accept, match)

	accept, match = rsOr1.Match_rs(&rsOr3)
	expect(t, "rsOr1 accepts and matches rsOr3", true, true, accept, match)

	accept, match = rsOr3.Match_rs(&rsOr1)
	expect(t, "rsOr3 accepts and matches rsOr1", true, true, accept, match)

	accept, match = rsOr4.Match_rs(&rsOr1)
	expect(t, "rsOr4 niether accepts and matches rsOr1", false, false, accept, match)

	accept, match = rsOr1.Match_rs(&rsOr4)
	expect(t, "rsOr1 niether accepts and matches rsOr4", false, false, accept, match)
}

func TestRuleSetRuleSetHybridMatch(t *testing.T) {
	//now test && and ||
	accept, match := rsAnd1.Match_rs(&rsOr1)
	expect(t, "rsAnd1 accepts and matches rsOr1", true, true, accept, match)

	accept, match = rsOr1.Match_rs(&rsAnd1)
	expect(t, "rsOr1 accepts and matches rsAnd1", true, true, accept, match)

	accept, match = rsAnd1.Match_rs(&rsOr4)
	expect(t, "rsAnd1 neither accepts not matches rsOr4", false, false, accept, match)

	accept, match = rsOr4.Match_rs(&rsAnd1)
	expect(t, "rsOr4 neither accepts not matches rsAnd1", false, false, accept, match)
}

func TestRuleSetRealWorld(t *testing.T) {
	var ip = makeIPRule("10.0.0.1")
	var port80 = makeTCPRule("80")
	var port443 = makeTCPRule("443")
	var home = makeServiceRule("/home")
	var pattern = ip.And(port80.Or(port443)).And(home)

	var request1 = makeIPRule("10.0.0.2").And(port80).And(makeServiceRule("/index"))

	accept, match := pattern.Match_rs(request1)
	expect(t, "request1 is accepted but does not match pattern", true, false, accept, match)

	var request2 = makeIPRule("10.0.0.1").And(port443).And(makeServiceRule("/home"))
	accept, match = pattern.Match_rs(request2)
	expect(t, "request2 is accepted and matched by pattern", true, true, accept, match)

	var request3 = makeIPRule("10.0.0.1").And(port80).And(makeServiceRule("/home"))
	accept, match = pattern.Match_rs(request3)
	expect(t, "request3 is accepted and matched by pattern", true, true, accept, match)

	var request4 = makeIPRule("10.0.0.1").And(makeTCPRule("9999")).And(home)
	accept, match = pattern.Match_rs(request4)
	expect(t, "request4 is accepted but not matched by pattern", true, false, accept, match)

	var request5 = makeIPRule("10.0.0.1").And(makeUDPRule("80")).And(makeServiceRule("/home"))
	accept, match = pattern.Match_rs(request5)
	expect(t, "request5 is not accepted nor matched by pattern", false, false, accept, match)
}

func TestCredentialMatch(t *testing.T) {
	var c1 = Credential{Name: "n1", Value: "v1"}
	var c2 = Credential{Name: "n2", Value: "v2"}
	if c1.Accept(&c1) != true {
		t.Errorf("c1 does not accept itself")
	}
	if c1.Accept(&c2) != false {
		t.Errorf("c1 accepts c2")
	}
}

func TestResourceMatch(t *testing.T) {
	var c1 = Credential{Name: "n1", Value: "v1"}
	var c2 = Credential{Name: "n2", Value: "v2"}

	var name1 = makeIPRule("10.0.0.1").And(makeTCPRule("80")).And(makeServiceRule("/home"))
	var resource1 = Resource{Name: name1, IdentifiedBy: &c1}

	var name2 = makeIPRule("10.0.0.2").And(makeTCPRule("80")).And(makeServiceRule("/home"))
	var resource2 = Resource{Name: name2, IdentifiedBy: &c1}

	accept, match := resource1.Match(&resource2)
	expect(t, "resource1 should accept but not match resource2", true, false, accept, match)

	accept, match = resource1.Match(&resource1)
	expect(t, "resource1 should accept and match resource1", true, true, accept, match)

	var resource3 = Resource{Name: name1, IdentifiedBy: &c2}
	accept, match = resource1.Match(&resource3)
	expect(t, "resource1 should accept but not match resource1", true, false, accept, match)
}

func TestPolicyMatch(t *testing.T) {
	var c1 = Credential{Name: "n1", Value: "v1"}

	var name1 = makeIPRule("10.0.0.1").And(makeTCPRule("80")).And(makeServiceRule("/home"))
	var resource1 = Resource{Name: name1, IdentifiedBy: &c1}

	var name2 = makeIPRule("10.0.0.2").And(makeTCPRule("80")).And(makeServiceRule("/home"))
	var resource2 = Resource{Name: name2, IdentifiedBy: &c1}

	var targetName = makeIPRule("10.0.0.1").And(makeTCPRule("80").Or(makeTCPRule("443"))).And(makeServiceRule("/home"))
	var targetResource = Resource{Name: targetName, IdentifiedBy: &c1}

	var forever = Duration{time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)}
	var everywhere = Location{"everywhere"}
	var nowhere = Location{"nowhere"}

	var policyEmpty = makePolicy(targetResource, nil, nil, forever, everywhere)

	valid, accept, allow := policyEmpty.Match(&resource1, &targetResource, time.Now(), &everywhere)
	if valid == false {
		t.Errorf("policy must be valid")
	}
	expect(t, "policyEmpty should accept but not allow resource1 to access targetResource", true, false, accept, allow)

	var policyDisallow = makePolicy(targetResource, &resource2, &resource1, forever, everywhere)
	valid, accept, allow = policyDisallow.Match(&resource1, &targetResource, time.Now(), &everywhere)
	expect(t, "policyDisallow should accept but not allow resource1 to access targetResource", true, false, accept, allow)

	var policyAllow = makePolicy(targetResource, &resource1, &resource2, forever, everywhere)
	valid, accept, allow = policyAllow.Match(&resource1, &targetResource, time.Now(), &everywhere)
	expect(t, "policyAllow should accept and allow resource1 to access targetResource", true, true, accept, allow)

	valid, accept, allow = policyAllow.Match(&resource2, &targetResource, time.Now(), &everywhere)
	expect(t, "policyAllow should accept but not allow resource2 to access targetResource", true, false, accept, allow)

	valid, accept, allow = policyAllow.Match(&resource1, &targetResource, time.Date(4000, 1, 1, 0, 0, 0, 0, time.UTC), &everywhere)
	if valid == true {
		t.Errorf("policyAllow is not valid that far in the future")
	}

	valid, accept, allow = policyAllow.Match(&resource1, &targetResource, time.Now(), &nowhere)
	expect(t, "policyAllow should not accept nor allow resource1 to access targetResource from nowhere", false, false, accept, allow)
}

func TestPolicyMatchDifferentSrcAndTarget(t *testing.T) {
	var c1 = Credential{Name: "n1", Value: "v1"}
	var forever = Duration{time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)}
	var everywhere = Location{"everywhere"}

	var tcp80Name = makeIPRule("10.0.0.1").And(makeTCPRule("80")).And(makeServiceRule("/home"))
	var tcp443Name = makeIPRule("10.0.0.1").And(makeTCPRule("443")).And(makeServiceRule("/home"))

	var tcp80Resource = Resource{Name: tcp80Name, IdentifiedBy: &c1}
	var tcp443Resource = Resource{Name: tcp443Name, IdentifiedBy: &c1}

	var tcp443Policy = makePolicy(tcp443Resource, &tcp80Resource, nil, forever, everywhere)

	valid, accept, match := tcp443Policy.Match(&tcp80Resource, &tcp443Resource, time.Now(), &everywhere)
	if valid == false || accept == false || match == false {
		t.Errorf("different src and target %v %v %v", valid, accept, match)
	}
}

func TestPolicyLineMatch(t *testing.T) {
	var c1 = Credential{Name: "n1", Value: "v1"}
	var forever = Duration{time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)}
	var everywhere = Location{"everywhere"}

	var tcp80Name = makeIPRule("10.0.0.1").And(makeTCPRule("80")).And(makeServiceRule("/home"))
	var tcp443Name = makeIPRule("10.0.0.1").And(makeTCPRule("443")).And(makeServiceRule("/home"))

	var tcp80Resource = Resource{Name: tcp80Name, IdentifiedBy: &c1}
	var tcp443Resource = Resource{Name: tcp443Name, IdentifiedBy: &c1}

	//this is tautological, but we're testing the policy line matcher not the deeper policy logic
	var tcp80Policy = makePolicy(tcp80Resource, &tcp80Resource, nil, forever, everywhere)
	var tcp443Policy = makePolicy(tcp443Resource, &tcp443Resource, nil, forever, everywhere)

	var tcp80PolicyLine = PolicyLine{OOperator: NONE, PPolicy: tcp80Policy}
	var tcp443PolicyLine = PolicyLine{OOperator: NONE, PPolicy: tcp443Policy}

	valid, accept, match := tcp80PolicyLine.Match(&tcp80Resource, &tcp80Resource, time.Now(), &everywhere)
	if valid == false || accept == false || match == false {
		t.Errorf("tcp80PolicyLine must match itself %v %v %v", valid, accept, match)
	}

	valid, accept, match = tcp80PolicyLine.Match(&tcp443Resource, &tcp80Resource, time.Now(), &everywhere)
	if valid == false || accept == false || match == true {
		t.Errorf("tcp443PolicyLine must not match tcp80 %v %v %v", valid, accept, match)
	}

	//this is self contradictory... but thats fine for this test.
	var tcp443AndTCP80PolicyLine = PolicyLine{OOperator: AND, PPolicy: nil, LArg: &tcp80PolicyLine, RArg: &tcp443PolicyLine}

	valid, accept, match = tcp443AndTCP80PolicyLine.Match(&tcp80Resource, &tcp80Resource, time.Now(), &everywhere)
	if valid == false || accept == true || match == true {
		t.Errorf("tcp80/443PolicyLine must not match 80 %v %v %v", valid, accept, match)
	}

	valid, accept, match = tcp443AndTCP80PolicyLine.Match(&tcp443Resource, &tcp443Resource, time.Now(), &everywhere)
	if valid == false || accept == true || match == true {
		t.Errorf("tcp80/443PolicyLine must not match 443 %v %v %v", valid, accept, match)
	}

	var tcp443OrTCP80PolicyLine = PolicyLine{OOperator: OR, PPolicy: nil, LArg: &tcp80PolicyLine, RArg: &tcp443PolicyLine}

	valid, accept, match = tcp443OrTCP80PolicyLine.Match(&tcp80Resource, &tcp80Resource, time.Now(), &everywhere)
	if valid == false || accept == false || match == false {
		t.Errorf("tcp80/443PolicyLine must match 80 %v %v %v", valid, accept, match)
	}

	valid, accept, match = tcp443OrTCP80PolicyLine.Match(&tcp443Resource, &tcp443Resource, time.Now(), &everywhere)
	if valid == false || accept == false || match == false {
		t.Errorf("tcp80/443PolicyLine must match 443 %v %v %v", valid, accept, match)
	}
}

func TestPolicyBundleMatch(t *testing.T) {
	var c1 = Credential{Name: "n1", Value: "v1"}
	var forever = Duration{time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)}
	var everywhere = Location{"everywhere"}

	var tcp80Name = makeIPRule("10.0.0.1").And(makeTCPRule("80")).And(makeServiceRule("/home"))
	var tcp443Name = makeIPRule("10.0.0.1").And(makeTCPRule("443")).And(makeServiceRule("/home"))

	var tcp80Resource = Resource{Name: tcp80Name, IdentifiedBy: &c1}
	var tcp443Resource = Resource{Name: tcp443Name, IdentifiedBy: &c1}

	var tcp80Policy = makePolicy(tcp80Resource, &tcp80Resource, nil, forever, everywhere)
	var tcp443Policy = makePolicy(tcp443Resource, &tcp443Resource, nil, forever, everywhere)
	//var tcp443ButNot80Policy = makePolicy(tcp443Resource, &tcp443Resource, &tcp80Resource, forever, everywhere)
	tcp80Policy.Description = "tcp80Policy"
	tcp443Policy.Description = "tcp443Policy"

	var tcp80PolicyLine = PolicyLine{OOperator: NONE, PPolicy: tcp80Policy}
	//var tcp443PolicyLine = PolicyLine{ OOperator: NONE, PPolicy: tcp443Policy }

	var emptyPB = PolicyBundle{FormatVersion: 0, PolicyVersion: 0, Description: "", Policies: []PolicyBase{}}

	valid, accept, allow := emptyPB.Match(&tcp80Resource, &tcp80Resource, time.Now(), &everywhere)
	if valid == true || accept == true || allow == true {
		t.Errorf("empty pb should not allow %v %v %v", valid, accept, allow)
	}

	var allowPB = PolicyBundle{FormatVersion: 0, PolicyVersion: 0, Description: "", Policies: []PolicyBase{tcp443Policy, &tcp80PolicyLine}}
	valid, accept, allow = allowPB.Match(&tcp80Resource, &tcp80Resource, time.Now(), &everywhere)

	if valid == false || accept == false || allow == false {
		t.Errorf("allow pb should  allow %v %v %v", valid, accept, allow)
	}

}

func TestPolicySerializeAndMatch(t *testing.T) {
	var c1 = Credential{Name: "n1", Value: "v1"}
	var forever = Duration{time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)}
	var everywhere = Location{"everywhere"}

	var tcp80Name = makeIPRule("10.0.0.1").And(makeTCPRule("80")).And(makeServiceRule("/home"))
	var tcp443Name = makeIPRule("10.0.0.1").And(makeTCPRule("443")).And(makeServiceRule("/home"))

	var tcp80Resource = Resource{Name: tcp80Name, IdentifiedBy: &c1}
	var tcp443Resource = Resource{Name: tcp443Name, IdentifiedBy: &c1}

	var tcp80Policy = makePolicy(tcp80Resource, &tcp80Resource, nil, forever, everywhere)
	var tcp443Policy = makePolicy(tcp443Resource, &tcp443Resource, nil, forever, everywhere)
	tcp80Policy.Description = "tcp80Policy"
	tcp443Policy.Description = "tcp443Policy"

	var tcp80PolicyLine = PolicyLine{OOperator: NONE, PPolicy: tcp80Policy}
	var allowPB = PolicyBundle{FormatVersion: 0, PolicyVersion: 0, Description: "", Policies: []PolicyBase{tcp443Policy, &tcp80PolicyLine}}

	serialized, err := json.Marshal(&allowPB)
	if err != nil {
		t.Errorf("Unable to serialize PolicyBundle: %v", err)
	}

	deserialized := &PolicyBundle{}
	if err = json.Unmarshal(serialized, deserialized); err != nil {
		t.Errorf("Unable to deserialize PolicyBundle: %v", err)
	}

	valid, accept, allow := deserialized.Match(&tcp80Resource, &tcp80Resource, time.Now(), &everywhere)

	if valid == false || accept == false || allow == false {
		t.Errorf("allow pb should  allow %v %v %v", valid, accept, allow)
	}
}
