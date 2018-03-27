/*
Copyright 2017 Kamil Pawlowski, Ignasi Barrera

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

/*
Package policy contains the PADME Policy defintion (v2) See relevant Padme Doc

The matchers in this code operate on two concepts: Accept & Match.
In the ESO (Enforcement Surface Onion) matches
are only possible if the Layer and Layer type are the same.
Otherwise they become don't care values. Accept covers the
concept of being at the same Layer, then match indicates
if the patterns match. Thus when operating
on rules (or groups of rules) the following truth values define
operations. (below A and !A mean accept and not accept, M and !M
mean match and not match).  Note that this structure means we
don't have to flatten Layer rules before we apply policies.

Does R1 match R2:

    R1 !A _  R2       = !A !M
    R1  A !M R2       =  A !M
    R1  A  M R2       =  A  M

Does R3 match R1 && R2:

    R1    &&    R2
    !A  _ && !A  _ = !A !M  // _ means don't care
    !A  _ &&  A !M =  A !M
    !A  _ &&  A  M =  A  M
     A !M && !A !M =  A !M
     A !M &&  A !M =  A !M  // !M && !M
     A !M &&  A  M =  A !M  // !M && M
     A  M &&  A !M =  A !M  //  M && !M
     A  M &&  A  M =  A  M

Does R1 match R1 || R2:

    Rr    ||    R2
    !A  _ || !A  _ = !A !M  // _ means don't care
    !A  _ ||  A !M =  A !M
    !A  _ ||  A  M =  A  M
     A !M || !A !M =  A !M
     A !M ||  A !M =  A !M  // !M || !M
     A !M ||  A  M =  A  M  // !M ||  M
     A  M ||  A !M =  A  M  //  M || !M
     A  M ||  A  M =  A  M

Generally Combining Truth Values after that its as follow:

    !A  _ && !A  _ = !A !M
    !A  _ &&  A  _ = !A !M
     A  _ && !A  _ = !A !M
     A  _ &&  A  _ = M && M // ie: whatever the two match values are

    !A  _ || !A  _ = !A !M
     A !M || !A  _ =  A !M
     A  M || !A  _ =  A  M
    !A  _ ||  A !M =  A !M
    !A  _ ||  A  M =  A  M
     A  _ ||  A  _ =  M || M // i.e. whatever the two match values are.

Why does this work this way? Lets say you have the following rules:

    SRC_IP=10.0.0.1 DEST_PORT=80 SVC=/foo

and the following request comes in:

    SRC_IP=10.0.0.1 DEST_PORT=443 SVC=/bar

Beacuse we do this one at rule at a time, SRC_IP must be allowed to partially match
but once we start composing SRC_IP and DEST_PORT or futher must fail.

When working with Policy objects to match an incoming resource, rules are pre-processed
to remove from the matching process those fields that describe the input resource are
not part of the Policy rule set. This is done because incoming resources will usually
have a complete and detailed property sets whilst policies may be configured to take into
account only certain fields.

For example, a typical TCP packet could be defined as:

    SRC_IP=10.0.0.1 SRC_PORT=5678 DST_IP=10.0.0.5 DEST_POST=80

And policies should be able to configure rules just to match DEST_PORT. For this reason,
only the fields defined in the relevant policies are taken into account when matching
incoming resources.
*/
package policy

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

var logger = log.New(os.Stdout, "", log.Lshortfile)

// Rule defines a pattern that can be evaluated in a given ESO layer
type Rule struct {
	Layer    string `json:"layer"`
	LType    string `json:"layer_type"`
	Pattern  string `json:"pattern"`
	disabled bool
}

// AllowedOperators is the list of operators that are allowed to be used in rules.
//
// Equality operators (=, !=) are used to compare explicit values.
//
// Numeric operators (>, <, >=, <=) can be used to configure rules to match numeric
// criterias. e.g. DEST_PORT<1014, TTL>5, etc.
//
// Range operators (in) can be used to match values in a given range. A common use case
// for this is to match packets in a given network. e.g. SRC_IP in 10.0.0.0/24
var AllowedOperators = []string{"=", ">", "<", "in", "!=", ">=", "<="}

// Expression represents a tokenized rule pattern that can be used by rule matchers and
// policies to extract the structured information of the field to match.
type Expression struct {
	Field string
	Value string
	Op    string
}

// Match implements a primitive rule matcher.
//
// This returns two values, the first indicates
// if the rule was applicable (Layer and and type matched)
// and if the pattern matched. If the former did
// not the latter cannot.
//
// Further developement must be done to provide different matchers
// for specific patterns/Layers
func (r *Rule) Match(r1 *Rule) (bool, bool) {
	if strings.Compare(r.Layer, r1.Layer) == 0 &&
		strings.Compare(r.LType, r1.LType) == 0 {
		return true, strings.Compare(r.Pattern, r1.Pattern) == 0
	}
	return false, false
}

// Expression parses the rule pattern and builds an Expression object that can be passed to
// marchers and used by policies that need access to the rule fields.
func (r *Rule) Expression() Expression {
	var expr Expression
	for _, op := range AllowedOperators {
		if idx := strings.Index(r.Pattern, op); idx != -1 {
			expr = Expression{
				Op:    op,
				Field: r.Pattern[:idx],
				Value: r.Pattern[idx+len(op):],
			}
		}
	}
	return expr
}

func (r *Rule) String() string {
	return fmt.Sprintf("Rule: %v/%v/%v", r.Layer, r.LType, r.Pattern)
}

// Operator that can be used in composite RuleSets and PolicyLines
type Operator int

// my go install did not like iota
const (
	AND = Operator(iota)
	OR
	NONE
)

// RuleSet := Rule | RuleSet AND RuleSet | RuleSet OR RuleSet
//
// Where RuleSet := Rule, operator == NONE and LArg == nil and RArg = nil
//
// Where RuleSet := RuleSet AND RuleSet | RuleSet OR RuleSet Operator == OR | Operator == AND, rule == nil
//
// When defining RuleSets for policies AND and OR are permissible
// When defining RuleSets to match for now we only support
// AND to make life simpler.
type RuleSet struct {
	OOperator Operator
	RRule     *Rule
	LArg      *RuleSet
	RArg      *RuleSet
}

// MatchRule evaluates if a rule matches a RuleSet
//
// This returns two values, the first indicates if
// any Layer/LType combination was applicable.
// The second is if there was a match.  There can
// be no match if there is no applicable Layer/LTypeCombo.
//
// We have LArg, RArg and r (the rule)
//
// AND works as follows:
// if r has the same Layer and type as LArg and RArg, then
// r must match both LArg and RArg.
// Otherwise it must just match one of them, completely
//
// OR works as follows:
// if r has the same Layer and type as LArg and RArg then
// r may match either of them.
// otherwise it must just match one of them completely
//
// The AND match here must be able to say: ip == foo and tcp port = bar
func (rs *RuleSet) MatchRule(r *Rule) (bool, bool) {
	if r.disabled {
		return true, true
	}
	if rs.OOperator == NONE {
		return rs.RRule.Match(r)
	}
	if rs.OOperator == AND {
		lAccept, lMatch := rs.LArg.MatchRule(r)
		//rules only apply at a given Layer, so
		//if lAccept is false, then its like it never
		//happened.

		//we can't short circuit because we need accept to
		//be correct
		rAccept, rMatch := rs.RArg.MatchRule(r)

		if rAccept && lAccept {
			return true, rMatch && lMatch
		}
		return lAccept || rAccept, lMatch || rMatch
	}

	if rs.OOperator == OR {
		//or is easier. if lhs accepts and matches, we're done
		//otherwise let rhs have a go.
		lAccept, lMatch := rs.LArg.MatchRule(r)
		if lAccept && lMatch {
			return true, true
		}
		rAccept, rMatch := rs.RArg.MatchRule(r)
		if rAccept && rMatch {
			return true, true

		}
		if lAccept || rAccept {
			return true, false
		}
	}
	return false, false
}

// Match recursively evaluates a RuleSet for another RuleSet
//
// This returns two values, the first indicates if
// any Layer/LType combination was applicable.
// The second if there was a match.
func (rs *RuleSet) Match(rs1 *RuleSet) (bool, bool) {
	if rs1.OOperator == NONE {
		return rs.MatchRule(rs1.RRule)
	}
	if rs1.OOperator == AND {
		lAccept, lMatch := rs.Match(rs1.LArg)
		if !lAccept {
			return false, false
		}
		rAccept, rMatch := rs.Match(rs1.RArg)
		if !rAccept {
			return false, false
		}
		return true, lMatch && rMatch
	}

	if rs1.OOperator == OR {
		lAccept, lMatch := rs.Match(rs1.LArg)
		if lAccept && lMatch {
			return true, true
		}
		rAccept, rMatch := rs.Match(rs1.RArg)
		if rAccept && rMatch {
			return true, true
		}
		if lAccept || rAccept {
			return true, false
		}
	}

	return false, false
}

// And creates a composite RuleSet using the AND Operator
func (rs *RuleSet) And(rs1 *RuleSet) *RuleSet {
	var ruleSet = RuleSet{OOperator: AND, RRule: nil, LArg: rs, RArg: rs1}
	return &ruleSet
}

// Or creates a composite RuleSet using the OR Operator
func (rs *RuleSet) Or(rs1 *RuleSet) *RuleSet {
	var ruleSet = RuleSet{OOperator: OR, RRule: nil, LArg: rs, RArg: rs1}
	return &ruleSet
}

// Map returns a copy of the RuleSet where the given function has been applied to
// all its child Rules.
func (rs *RuleSet) Map(function func(*Rule) Rule) *RuleSet {
	var rule Rule
	var left, right *RuleSet

	if rs.RRule != nil {
		rule = function(rs.RRule)
	}
	if rs.LArg != nil {
		left = rs.LArg.Map(function)
	}
	if rs.RArg != nil {
		right = rs.RArg.Map(function)
	}

	return &RuleSet{OOperator: rs.OOperator, RRule: &rule, LArg: left, RArg: right}
}

// Foreach applies the given function to the rules in the RuleSet
func (rs *RuleSet) Foreach(function func(*Rule)) {
	if rs.RRule != nil {
		function(rs.RRule)
	}
	if rs.LArg != nil {
		rs.LArg.Foreach(function)
	}
	if rs.RArg != nil {
		rs.RArg.Foreach(function)
	}
}

func (rs *RuleSet) String() string {
	if rs.OOperator == NONE {
		return rs.RRule.String()
	}
	if rs.OOperator == AND {
		return fmt.Sprintf("(%v AND %v)", rs.LArg.String(), rs.RArg.String())
	}
	return fmt.Sprintf("(%v OR %v)", rs.LArg.String(), rs.RArg.String())
}

// Credential will expand as we support
// a greater number of different kinds of credentials.
// expect this to change/expand
type Credential struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Accept implements a basic credential matching, by Name match
func (c *Credential) Accept(c1 *Credential) bool {
	return strings.Compare(c.Name, c1.Name) == 0 &&
		strings.Compare(c.Value, c1.Value) == 0
}

func (c *Credential) String() string {
	return fmt.Sprintf("Credential: %v/%v", c.Name, c.Value)
}

// Resource type identifies a resource
type Resource struct {
	Name         *RuleSet    `json:"rules"`
	IdentifiedBy *Credential `json:"identified_by"`

	// When matching an input resource against a resource defined by a Policy, we just have
	// to consider the rules that apply to the fields defined in the policy. The rest should
	// be ignored.
	fieldsToMatch []string
}

// getRulesToMatch builds a copy of the input resource with all the rules that should not be applied
// marked to be ignored. Let's use a copy to perform the local match to avoid affecting
// the behavior of later stages of the matching system
func getRulesToMatch(fieldsToMatch []string, input *Resource) *RuleSet {
	return input.Name.Map(func(rule *Rule) Rule {
		expr := rule.Expression()
		r := Rule{
			LType:    rule.LType,
			Layer:    rule.Layer,
			Pattern:  rule.Pattern,
			disabled: true,
		}
		for _, f := range fieldsToMatch {
			if f == expr.Field {
				r.disabled = false
			}
		}
		return r
	})
}

// When matching an input resource against a resource defined by the policy, just consider
// the rules applied to the fields defined in the policy and ignore the rest
func processRuleFields(r *Resource) {
	if len(r.fieldsToMatch) == 0 {
		r.Name.Foreach(func(rule *Rule) {
			r.fieldsToMatch = append(r.fieldsToMatch, rule.Expression().Field)
		})
	}
}

// Match determines if a Resource matches a given Resource r
// This means that the ruleset accepts the rule in r1
// and identified by accepts the resource.
//
// Return (accept, match)
//	accept - indicates a rule level accept.
//	match  - indicate a rule level match and credential acceptance.
func (r *Resource) Match(r1 *Resource) (bool, bool) {
	processRuleFields(r)
	rulesToMatch := getRulesToMatch(r.fieldsToMatch, r1)

	accept, match := r.Name.Match(rulesToMatch)
	if !accept {
		return false, false
	}

	if match {
		if r.IdentifiedBy.Accept(r1.IdentifiedBy) {
			return true, true
		}
		return true, false

	}
	return true, false
}

func (r *Resource) String() string {
	return fmt.Sprintf("Resource: %v id by %v", r.Name.String(), r.IdentifiedBy.String())
}

// Duration defines when policies come into and go out of effect
type Duration struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func (d *Duration) String() string {
	return fmt.Sprintf("%v to %v", d.Start, d.End)
}

// Location defines the location of a Policy.
// As we refine location support this will become more full featured
type Location struct {
	Name string `json:"name"`
}

// Match implaments  a simple total equality location matcher
func (l *Location) Match(l1 *Location) bool {
	if strings.Compare(l.Name, l1.Name) == 0 {
		return true
	}
	return false
}

func (l *Location) String() string {
	return fmt.Sprintf("%v", l.Name)
}

// Contents are used to pass opaque plugin specific information
type Contents struct {
	PluginID string
	Blob     []byte
}

// PolicyBase is an Interface used for matching in PolicyBundle */
type PolicyBase interface {

	// Match checks if a given source Resource can access a given target Resource
	//
	// Given a source, a target, a policy, and a time, determine
	// if source can access target via the specific subclass of PolicyBase
	//
	// Parameters:
	// source - Resource making the request
	// target - Resource being accessed
	// when   - time when the request is being made
	// where  - a location where the policy is being evaluated
	//
	// return (valid, accept, allow)
	//	valid  - indicates if the policy is valid at the time of evaluation
	//	    if not, then accept and allow are meaningless.
	//	accept - indicates if the policy applies to this target and location
	//	allow  - indicates if permission is granted or denied
	Match(source *Resource, target *Resource, when time.Time, where *Location) (bool, bool, bool)

	String() string
}

// PolicyFormatVersion is the version of the policy schema
const PolicyFormatVersion uint64 = 0

// Policy definition
type Policy struct {
	UUID          string      `json:"uuid"`
	FormatVersion uint64      `json:"format_version"`
	PolicyVersion uint64      `json:"policy_version"`
	Description   string      `json:"description"`
	Target        Resource    `json:"target"`
	Allowed       []*Resource `json:"allowed"`
	Disallowed    []*Resource `json:"disallowed"`
	Timeline      Duration    `json:"timeline"`
	Rate          uint64      `json:"rate"`
	LLocation     Location    `json:"location"`
	CContents     []*Contents `json:"contents,omitempty"`
	Signature     string      `json:"signature"`
}

// Match determinies, given a source, a target, a policy, and a time,
// if source can access target via the policy.
//
// Parameters:
//	source - Resource making the request
//	target - Resource being accessed
//	when   - time when the request is being made
//	where  - a location where the policy is being evaluated
//
// Return: (valid, accept, allow)
//	valid  - indicates if the policy is valid at the time of evaluation
//		 if not, then accept and allow are meaningless.
//	accept - indicates if the policy applies to this target and location
//	allow  - indicates if permission is granted or denied
func (p *Policy) Match(source *Resource, target *Resource, when time.Time, where *Location) (bool, bool, bool) {
	if when.Before(p.Timeline.Start) || when.After(p.Timeline.End) {
		return false, false, false
	}

	if !p.LLocation.Match(where) {
		return true, false, false
	}

	// policy must apply to the target
	// source must be allowed
	//
	//we could short circuit here and use accept, but this is clearer.
	//note that returning from this call what accept means changes vs
	//resources.
	_, match := p.Target.Match(target)
	if match == true {
		//apply black list first to exclude, then apply white list to allow
		for _, element := range p.Disallowed {
			if element == nil {
				continue
			}
			// here accept must be true or the policy is malformed.
			_, matchElement := element.Match(source)
			if matchElement == true {
				return true, true, false
			}
		}

		//once we're through all the disallowed, see if we allow
		for _, element := range p.Allowed {
			if element == nil {
				continue
			}

			_, matchElement := element.Match(source)
			if matchElement == true {
				return true, true, true
			}
		}

		return true, true, false
	}
	return true, false, false
}

func (p *Policy) String() string {
	return fmt.Sprintf("%v:%v:%v\n\ttarget: %v",
		p.FormatVersion,
		p.PolicyVersion,
		p.Description,
		p.Target.String())
}

// PolicyLine := Policy | PolicyLine AND PolicyLine | PolicyLine OR PolicyLine
//
// Where PolicyLine := Policy, opeartor == NONE and LArg == nil and RArg = nil
//
// Where PolicyLine := PolicyLine AND PolicyLine | PolicyLine OR PolicyLine Operator == OR | Operator == AND, policy == nil
type PolicyLine struct {
	OOperator Operator
	PPolicy   *Policy
	LArg      *PolicyLine
	RArg      *PolicyLine
}

// Match tests a request against a policy line. This works identically
// to the Match function on policies, except that boolean operators are allowed.
//
// Note that you can realy shoot yourself in the foot with OR operator, so
// be carefull.
//
// See (p* Policy) Match for inputs and outputs
func (p *PolicyLine) Match(source *Resource, target *Resource, when time.Time, where *Location) (bool, bool, bool) {
	if p.OOperator == NONE {
		return p.PPolicy.Match(source, target, when, where)
	}

	if p.OOperator == AND {
		lValid, lAccept, lMatch := p.LArg.Match(source, target, when, where)
		//we may want to evaluate match anyway so that we can help debug policies
		if !lValid {
			return false, false, false
		}
		rValid, rAccept, rMatch := p.RArg.Match(source, target, when, where)
		if !rValid {
			return false, false, false
		}

		return true, lAccept && rAccept, lMatch && rMatch
	}

	if p.OOperator == OR {
		lValid, lAccept, lMatch := p.LArg.Match(source, target, when, where)
		if lValid && lAccept && lMatch {
			return true, true, true
		}
		rValid, rAccept, rMatch := p.RArg.Match(source, target, when, where)

		return lValid || rValid, lAccept || rAccept, lMatch || rMatch
	}

	return false, false, false
}

func (p *PolicyLine) String() string {
	if p.OOperator == NONE {
		return p.PPolicy.String()
	} else if p.OOperator == AND {
		return fmt.Sprintf("(%v AND %v)", p.LArg.String(), p.RArg.String())
	} else { //or
		return fmt.Sprintf("(%v OR %v)", p.LArg.String(), p.RArg.String())
	}
}

// FilterPolicies filters the policies in the current PolicyLine that satisfy the given predicate
func (p *PolicyLine) FilterPolicies(predicate PolicyPredicate) []*Policy {
	var policies []*Policy

	if p.PPolicy != nil && predicate(p.PPolicy) {
		policies = append(policies, p.PPolicy)
	}
	if p.LArg != nil {
		policies = append(policies, p.LArg.FilterPolicies(predicate)...)
	}
	if p.RArg != nil {
		policies = append(policies, p.RArg.FilterPolicies(predicate)...)
	}

	return policies
}

// PolicyBundleFormatVersion is the version of the Policy Bundle schema
const PolicyBundleFormatVersion uint64 = 0

// PolicyBundle groups policies together
type PolicyBundle struct {
	FormatVersion uint64       `json:"format_version"`
	PolicyVersion uint64       `json:"policy_version"`
	Description   string       `json:"description"`
	Policies      []PolicyBase `json:"policies"`
}

// Match checks all the policies in a bundle, attempting to see if the request is allowed.
//
// A request is allowed only if it has been specifically allowed. Only valid policies, that
// accept the request are considered for allow/deny decisions.
// (i.e. policies that are enforce, at the location, and where the request parameters match).
//
// A policy must explicitly allow the request. If no policy covers this traffic, the request
// is denied. As soon as a policy is found that denies the request no futher searching is done.
//
// Parameters:
//	source - Resource making the request
//	target - Resource being accessed
//	when   - time when the request is being made
//	where  - a location where the policy is being evaluated
//
// Return: (valid, accept, allow)
//	valid  - indicates if any policy was valid at the time of evaluation
//		 if not, then accept and allow are meaningless.
//	accept - indicates if a valid policy applied to this target and location
//	allow  - indicates if permission is granted or denied
func (p *PolicyBundle) Match(source *Resource, target *Resource, when time.Time, where *Location) (bool, bool, bool) {
	var valid = false
	var accept = false
	var allow = false

	for _, element := range p.Policies {
		if element == nil {
			continue
		}
		eValid, eAccept, eAllow := element.Match(source, target, when, where)
		if !eValid {
			continue
		}
		valid = true
		if !eAccept {
			continue
		}
		// we have a valid, policy that accepts the request.
		// if the request is not allowed, we're done.
		// if it allowed, keep going to see if there is a subsequent
		// rule that denies it. (this may get us into trouble, in some cases)
		accept = true
		if !eAllow {
			return true, true, false
		}
		allow = true
	}
	return valid, accept, allow
}

// PolicyPredicate defines a predicate used to filter policies in a PolicyBundle
type PolicyPredicate func(*Policy) bool

// Filter returns the policies in this bundle that satisfy the given predicate
//
// When the bundle contains PolicyLine objects, filtering will traverse the PolicyLine
// structure and return all its policies that match the given predicate.
func (p *PolicyBundle) Filter(predicate PolicyPredicate) []*Policy {
	var policies []*Policy
	for _, base := range p.Policies {
		switch pb := base.(type) {
		case *Policy:
			if predicate(pb) {
				policies = append(policies, pb)
			}
		case *PolicyLine:
			policies = append(policies, pb.FilterPolicies(predicate)...)
		}
	}
	return policies
}
