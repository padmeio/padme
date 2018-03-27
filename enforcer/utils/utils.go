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

// Package utils provides utility methods for the enforcer package
package utils

import (
	"fmt"
	"net"
	"strings"

	"github.com/padmeio/padme/enforcer/plugins"
	"github.com/padmeio/padme/policy"
)

// NewResource takes a set of Rules and credentials and builds a Resource object to be
// evaluated against existing policies.
func NewResource(properties []*policy.Rule, credential *policy.Credential) (*policy.Resource, error) {
	resource := &policy.Resource{IdentifiedBy: credential}
	if len(properties) == 0 {
		return nil, fmt.Errorf("at least one property must be defined")
	}
	ruleset := &policy.RuleSet{OOperator: policy.NONE, RRule: properties[0]}
	if len(properties) > 1 {
		for _, rule := range properties[1:] {
			ruleset = ruleset.And(&policy.RuleSet{OOperator: policy.NONE, RRule: rule})
		}
	}
	resource.Name = ruleset
	return resource, nil
}

// PluginFilter returns a predicate that can be used to filter policies
// that apply to the given plugin
func PluginFilter(plugin plugins.Plugin) policy.PolicyPredicate {
	return func(p *policy.Policy) bool {
		if p.CContents != nil {
			for _, content := range p.CContents {
				if content.PluginID == plugin.ID() {
					return true
				}
			}
		}
		return false
	}
}

// LocalAddresses returns the list of local IP addresses
func LocalAddresses() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var res []string
	for _, addr := range addrs {
		ip := strings.Split(addr.String(), "/")[0]
		res = append(res, ip)
	}
	return res, nil
}

// AddressesToResource takes a list of IP addresses and returns a Resource representing
// all those addresses.
// The returned Resource will be assembled using the OR operator.
func AddressesToResource(addresses []string, credentials *policy.Credential) (*policy.Resource, error) {
	if len(addresses) == 0 {
		return nil, fmt.Errorf("empty address list")
	}

	rule := &policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=" + addresses[0]}
	rules := &policy.RuleSet{OOperator: policy.NONE, RRule: rule}

	if len(addresses) > 1 {
		for _, addr := range addresses[1:] {
			r := &policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=" + addr}
			rules = rules.Or(&policy.RuleSet{OOperator: policy.NONE, RRule: r})
		}
	}

	return &policy.Resource{Name: rules, IdentifiedBy: credentials}, nil
}
