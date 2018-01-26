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

/*
 * PADME Policy defintion (v2) See relevant Padme Doc
 *
 * The matchers in this code operate on two concepts: 
 * Accept & Match
 * In the ESO (Enforcement Surface Onion) matches 
 * are only possible if the Layer and Layer type are the same.
 * Otherwise they become don't care values. Accept covers the
 * concept of being at the same Layer, then match indicates 
 * if the patterns match. Thus when operating
 * on rules (or groups of rules) the following truth values define
 * operations. (below A and !A mean accept and not accept, M and !M 
 * mean match and not match).  Note that this structure means we
 * don't have to flatten Layer rules before we apply policies.
 *
 * Does R1 match R2:
 * R1 !A _  R2       = !A !M
 * R1  A !M R2       =  A !M
 * R1  A  M R2       =  A  M
 *
 * Does R3 match R1 && R2:
 * R1    &&    R2
 * !A  _ && !A  _ = !A !M  // _ means don't care
 * !A  _ &&  A !M =  A !M  
 * !A  _ &&  A  M =  A  M 
 *  A !M && !A !M =  A !M
 *  A !M &&  A !M =  A !M  // !M && !M
 *  A !M &&  A  M =  A !M  // !M && M
 *  A  M &&  A !M =  A !M  //  M && !M
 *  A  M &&  A  M =  A  M
 *
 * Does R1 match R1 || R2:
 * Rr    ||    R2
 * !A  _ || !A  _ = !A !M  // _ means don't care
 * !A  _ ||  A !M =  A !M  
 * !A  _ ||  A  M =  A  M 
 *  A !M || !A !M =  A !M
 *  A !M ||  A !M =  A !M  // !M || !M
 *  A !M ||  A  M =  A  M  // !M ||  M
 *  A  M ||  A !M =  A  M  //  M || !M
 *  A  M ||  A  M =  A  M
 *
 * Generally Combining Truth Values after that its as follow:
 * !A  _ && !A  _ = !A !M
 * !A  _ &&  A  _ = !A !M
 *  A  _ && !A  _ = !A !M
 *  A  _ &&  A  _ = M && M // ie: whatever the two match values are
 * 
 * !A  _ || !A  _ = !A !M
 *  A !M || !A  _ =  A !M
 *  A  M || !A  _ =  A  M
 * !A  _ ||  A !M =  A !M
 * !A  _ ||  A  M =  A  M
 *  A  _ ||  A  _ =  M || M // i.e. whatever the two match values are.
 *
 * Why does this work this way?... 
 * Lets say you have the following rules: SRC IP = 10.0.0.1, DEST_PORT=80 SVC=/foo
 * and the following request comes in:
 * SRC IP = 10.0.0.1 DEST_PORT=443 SVC=/bar
 * Beacuse we do this one at rule at a time, SRC IP must be allowed to partially match
 * but once we start composing SRC_IP and DEST_PORT or futher must fail.
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

/**
 * Defintion of Rule and RuleSet for identification
 */
type Rule struct {
    Layer string    `json:"layer"`
    LType string    `json:"layer_type"`
    Pattern string  `json:"pattern"`
}

/**
 * A primitive rule matcher. 
 * 
 * This returns two values, the first indicates
 * if the rule was applicable (Layer and and type matched)
 * and if the pattern matched. If the former did 
 * not the latter cannot. 
 *
 * Further developement must be done to provide different matchers
 * for specific patterns/Layers
 */
func (r* Rule) Match(r1* Rule) (bool, bool) {
    //logger.Printf("%s/%s/%s match %s/%s/%s", r.Layer, r.LType, r.Pattern, r1.Layer, r1.LType, r1.Pattern)
    if (strings.Compare(r.Layer, r1.Layer) == 0 &&
        strings.Compare(r.LType, r1.LType) == 0) {
      return true, strings.Compare(r.Pattern, r1.Pattern) == 0
    }
    return false, false
}

func (r* Rule) String() string {
    return fmt.Sprintf("Rule: %v/%v/%v", r.Layer, r.LType, r.Pattern)
}

type Operator int

//my go install did not like iota
const (
    AND Operator = 0
    OR Operator = 1 
    NONE Operator = 2
)

/**
 * RuleSets := Rule| RuleSet AND RuleSet | RuleSet OR RuleSet
 *
 * Where RuleSet := Rule, operator == NONE and
 *   LArg == nil and RArg = nil
 * Where RuleSet := RuleSet AND RuleSet | RuleSet OR RuleSet
 *   Operator == OR or == AND, rule == nil
 *
 * When defining RuleSets for policies AND and OR are permissible
 * When defining RuleSets to match for now we only support
 * AND to make life simpler.
 */
type RuleSet struct {
    OOperator Operator
    RRule *Rule
    LArg *RuleSet
    RArg *RuleSet
}

/**
 * Does a rule match a RuleSet
 *
 * this returns two values, the first indicates if 
 * any Layer/LType combination was applicable.
 * The second is if there was a match.  There can
 * be no match if there is no applicable Layer/LTypeCombo.
 *
 * We have LArg, RArg and r (the rule)
 * AND works as follows:
 * if r has the same Layer and type as LArg and RArg, then 
 * r must match both LArg and RArg.
 * Otherwise it must just match one of them, completely
 *
 * OR works as follows:
 * if r has the same Layer and type as LArg and RArg then
 * r may match either of them.
 * otherwise it must just match one of them completely
 * 
 * The AND match here must be able to say: ip == foo and tcp port = bar
 */
func (rs* RuleSet) Match_r (r* Rule) (bool,bool) {
    if (rs.OOperator == NONE) { return rs.RRule.Match(r) }
    if (rs.OOperator == AND) {
        lAccept, lMatch := rs.LArg.Match_r(r);
        //rules only apply at a given Layer, so 
        //if lAccept is false, then its like it never
        //happened.

        //we can't short circuit because we need accept to
        //be correct
        rAccept, rMatch := rs.RArg.Match_r(r);

        if (rAccept && lAccept) {
            return true , rMatch && lMatch
        }
        return lAccept || rAccept, lMatch || rMatch
    }

    if (rs.OOperator == OR) {
        //or is easier. if lhs accepts and matches, we're done
        //otherwise let rhs have a go.
        lAccept, lMatch := rs.LArg.Match_r(r);
        if (lAccept && lMatch) { return true, true; }
        rAccept, rMatch := rs.RArg.Match_r(r);
        if (rAccept && rMatch) { return true, true; }
        if (lAccept || rAccept) { return true, false; }
    }
    return false, false
}

/** 
 * Recurseive RulesSet evaluation for another ruleset
 *
 * This returns two values, the first indicates if
 * any Layer/LType combination was applicable.
 * The second if there was a match.
 */
func (rs* RuleSet) Match_rs (rs1* RuleSet) (bool, bool) {
    if (rs1.OOperator == NONE) {
        return rs.Match_r(rs1.RRule);
    }
    if (rs1.OOperator == AND) {
        lAccept, lMatch := rs.Match_rs(rs1.LArg);
        if (!lAccept) { return false, false; }
        rAccept, rMatch := rs.Match_rs(rs1.RArg);
        if (!rAccept) { return false, false; }
        return true, lMatch && rMatch
    }

    if (rs1.OOperator == OR) {
        lAccept, lMatch := rs.Match_rs(rs1.LArg);
        if (lAccept && lMatch) { return true, true; }
        rAccept, rMatch := rs.Match_rs(rs1.RArg);
        if (rAccept && rMatch) { return true, true; }
        if (lAccept || rAccept) { return true, false; }
    }
    
    return false, false
}

func (rs* RuleSet) And(rs1* RuleSet) *RuleSet {
    var ruleSet = RuleSet{ OOperator: AND, RRule: nil, LArg: rs, RArg: rs1 }
    return &ruleSet
}

func (rs* RuleSet) Or(rs1* RuleSet) *RuleSet {
    var ruleSet = RuleSet{ OOperator: OR, RRule: nil, LArg: rs, RArg: rs1 }
    return &ruleSet
}

func (rs* RuleSet) String() string {
    if (rs.OOperator == NONE) {
        return rs.RRule.String()
    }
    if (rs.OOperator == AND) {
        return fmt.Sprintf("(%v AND %v)", rs.LArg.String(), rs.RArg.String())
    } else { // OR
        return fmt.Sprintf("(%v OR %v)", rs.LArg.String(), rs.RArg.String())
    }
}

/**
 * Credential will expand as we support 
 * a greater number of different kinds of credentials.
 * expect this to change/expand
 */
type Credential struct {
    Name string		`json:"name"`
    Value string	`json:"value"`
}

/**
 * Basic credential matching, by Name match
 */
func (c* Credential) Accept(c1* Credential) (bool){
    return strings.Compare(c.Name, c1.Name) == 0 &&
        strings.Compare(c.Value, c1.Value) == 0
}

func (c* Credential) String() string {
    return fmt.Sprintf("Credential: %v/%v", c.Name, c.Value)
}

/** Resource Identifier */
type Resource struct {
    Name* RuleSet		`json:"rules"`
    IdentifiedBy* Credential	`json:identified_by"`
}

/** 
 * Determine a resource match with Resource r
 * This means that the ruleset accepts the rule in r1
 * and identified by accepts the resource.
 *
 * return accept, match - accept indicates a rule
 * level accept. match indicate a rule level match
 * and credential acceptance.
 */
func (r* Resource) Match (r1* Resource) (bool, bool) {
    accept, match := r.Name.Match_rs(r1.Name)
    if (!accept) { return false, false }

    if (match) {
        if (r.IdentifiedBy.Accept(r1.IdentifiedBy)) {
            return true, true;
        } else {
            return true, false
        }
    } else {
        return true, false
    }
}

func (r* Resource) String() string {
    return fmt.Sprintf("Resource: %v id by %v", r.Name.String(), r.IdentifiedBy.String())
}

/** Defines when policies come into and go out of effect*/
type Duration struct {
    Start time.Time	`json:"start"`
    End time.Time	`json:"end"`
}

func (d* Duration) String() string {
    return fmt.Sprintf("%v to %v", d.Start, d.End)
}

/** As we refine location support this will become more full featured */
type Location struct {
    Name string	    `json:"name"`
}

/** a simple total equality location matcher */
func (l* Location) Match(l1 *Location) bool {
    if (strings.Compare(l.Name , l1.Name) == 0) {
        return true
    }
    return false
}

func (l* Location) String() string {
    return fmt.Sprintf("%v", l.Name)
}

/** Contents are used to pass opaque plugin specific information */
type Contents struct {
    PluginId string
    Blob []byte
}

/** Interface used for matching in PolicyBundle */
type PolicyBase interface {

    /**
     * given a source, a target, a policy, and a time, determine
     * if source can access target via the specific subclass of PolicyBase
     *
     * Parameters:
     * source - Resource making the request
     * target - Resource being accessed
     * when   - time when the request is being made
     * where  - a location where the policy is being evaluated
     *
     * return (valid, accept, allow) 
     *  valid  - indicates if the policy is valid at the time of evaluation 
     *      if not, then accept and allow are meaningless.
     *  accept - indicates if the policy applies to this target and location
     *  allow  - indicates if permission is granted or denied
    */
    Match(source* Resource, target* Resource, when time.Time, where* Location) (bool, bool, bool)

    /**
     * for printing of policies
     */
    String() string
}

/** This is the version of the policy schema */
const PolicyFormatVersion uint64 = 0

/** Defintion of a Policy */
type Policy struct {
    FormatVersion uint64	`json:"format_version"`
    PolicyVersion uint64	`json:"policy_version"`
    Description string		`json:"description"`
    Target Resource		`json:"target"`
    Allowed []*Resource		`json:"allowed"`
    Disallowed []*Resource	`json:"disallowed"`
    Timeline Duration		`json:"timeline"`
    Rate uint64			`json:"rate"`
    LLocation Location		`json:"location"`
    CContents []*Contents	`json:"contents,omitempty"`
    Signature string		`json:"signature"`
}

/**
 * given a source, a target, a policy, and a time, determine
 * if source can access target via the policy
 *
 * Parameters:
 * source - Resource making the request
 * target - Resource being accessed
 * when   - time when the request is being made
 * where  - a location where the policy is being evaluated
 *
 * return (valid, accept, allow) 
 *  valid  - indicates if the policy is valid at the time of evaluation 
 *      if not, then accept and allow are meaningless.
 *  accept - indicates if the policy applies to this target and location
 *  allow  - indicates if permission is granted or denied
 */
func (p* Policy) Match(source* Resource, target* Resource, when time.Time, where* Location) (bool, bool, bool) {
    if (when.Before(p.Timeline.Start) || when.After(p.Timeline.End)) {
        return false, false, false
    }

    if (!p.LLocation.Match(where)) {
        return true, false, false
    }

    // policy must apply to the target
    // source must be allowed
    //
    //we could short circuit here and use accept, but this is clearer.
    //note that returning from this call what accept means changes vs
    //resources.
    _, match := p.Target.Match(target)
    if (match == true) {
        //apply black list first to exclude, then apply white list to allow
        for _, element := range p.Disallowed {
            if (element == nil) { continue }
            // here accept must be true or the policy is malformed.
            _, matchElement := element.Match(source)
            if (matchElement == true) {
                return true, true, false
            }
        }

        //once we're through all the disallowed, see if we allow
        for _, element := range p.Allowed {
            if (element == nil) { continue }

            _, matchElement := element.Match(source)
            if (matchElement == true) {
                return true, true, true
            }
        }

        return true, true, false
    } else {
        return true, false, false
    }
}

func (p* Policy) String() string {
    return fmt.Sprintf("%v:%v:%v\n\ttarget: %v", 
        p.FormatVersion, 
        p.PolicyVersion, 
        p.Description,
        p.Target.String())
}

/**
 * PolicyLine := Policy | PolicyLine AND PolicyLine | PolicyLine OR PolicyLine
 *
 * Where PolicyLine := Policy, opeartor == NONE and
 *   LArg == nil and RArg = nil
 * Where PolicyLine := PolicyLine AND PolicyLine | PolicyLine OR PolicyLine 
 *   Operator == OR or == AND, policy == nil
 */
type PolicyLine struct {
    OOperator Operator
    PPolicy *Policy
    LArg* PolicyLine
    RArg* PolicyLine
}

/**
 * test a request against a policy line. This works identically 
 * to the Match function on policies, except that boolean operators are allowed.
 * 
 * Note that you can realy shoot yourself in the foot with OR operator, so
 * be carefull. 
 *
 * see (p* Policy) Match for inputs and outputs
 */
func (p* PolicyLine) Match(source *Resource, target* Resource, when time.Time, where* Location) (bool, bool, bool) {
    if (p.OOperator == NONE){
        return p.PPolicy.Match(source, target, when, where)
    }

    if (p.OOperator == AND) {
        lValid, lAccept, lMatch := p.LArg.Match(source, target, when, where)
        //we may want to evaluate match anyway so that we can help debug policies
        if (!lValid) { return false, false, false }
        rValid, rAccept, rMatch := p.RArg.Match(source, target, when, where)
        if (!rValid) { return false, false, false }

        return true, lAccept && rAccept, lMatch && rMatch
    }

    if (p.OOperator == OR) {
        lValid, lAccept, lMatch := p.LArg.Match(source, target, when, where)
        if (lValid && lAccept && lMatch) { return  true, true, true }
        rValid, rAccept, rMatch := p.RArg.Match(source, target, when, where)

        return lValid || rValid, lAccept || rAccept, lMatch || rMatch
    }

    return false, false, false
}

func (p* PolicyLine) String() string {
    if (p.OOperator == NONE) {
        return p.PPolicy.String()
    } else if (p.OOperator == AND) {
        return fmt.Sprintf("(%v AND %v)", p.LArg.String(), p.RArg.String())
    } else { //or
        return fmt.Sprintf("(%v OR %v)", p.LArg.String(), p.RArg.String())
    }
}

/** This is the version of the Policy Bundle schema */
const PolicyBundleFormatVersion uint64 = 0

type PolicyBundle struct {
    FormatVersion uint64	`json:"format_version"`
    PolicyVersion uint64	`json:"policy_version"`
    Description string		`json:"description"`
    Policies []PolicyBase	`json:"policies"`
}

/**
 * Check all the policies in a bundle, attempting to see if the request is allowed.
 * A request is allowed only if it has been specifically allowed. Only valid policies, that
 * accept the request are considered for allow/deny decisions.  
 * (i.e. policies that are enforce, at the location, and where the request parameters match).
 * 
 * A policy must explicitly allow the request. If no policy covers this traffic, the request
 * is denied. As soon as a policy is found that denies the request no futher searching is done.
 *
 * Parameters:
 * source - Resource making the request
 * target - Resource being accessed
 * when   - time when the request is being made
 * where  - a location where the policy is being evaluated
 *
 * return (valid, accept, allow) 
 *  valid  - indicates if any policy was valid at the time of evaluation 
 *      if not, then accept and allow are meaningless.
 *  accept - indicates if a valid policy applied to this target and location
 *  allow  - indicates if permission is granted or denied
 */
func (p* PolicyBundle) Match(source *Resource, target* Resource, when time.Time, where* Location) (bool, bool, bool) {
    var valid = false
    var accept = false
    var allow = false

    for _, element := range p.Policies {
        if (element == nil) { continue }
        eValid, eAccept, eAllow := element.Match(source, target, when, where)
        if (!eValid) { continue; }
        valid = true;
        if (!eAccept) { continue; }
        // we have a valid, policy that accepts the request.
        // if the request is not allowed, we're done.
        // if it allowed, keep going to see if there is a subsequent
        // rule that denies it. (this may get us into trouble, in some cases)
        accept = true;
        if (!eAllow) { return true, true, false }
        allow = true;
    }
    return valid, accept, allow
}
