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

package enforcer

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	store "github.com/padmeio/padme/enforcer/store/filesystem"
	"github.com/padmeio/padme/policy"
)

var (
	testFile  = fmt.Sprintf("%v/src/github.com/padmeio/padme/policy/test_policy.json", os.Getenv("GOPATH"))
	bundle    = loadTestPolicyFile(testFile)
	testStore = store.LocalPolicyRepository{FilePath: "/tmp/padme-enforcer.json"}

	// List of all policies and all policies that define plugin data
	totalPolicies  = len(bundle.Filter(func(p *policy.Policy) bool { return true }))
	pluginPolicies = len(bundle.Filter(func(p *policy.Policy) bool {
		return p.CContents != nil && len(p.CContents) > 0
	}))

	credentials = &policy.Credential{Name: "PADME", Value: "PADME"}
	location    = &policy.Location{Name: "PADME"}
)

// lastEvent is a PolicyEventHandler that keeps track of the last fired event
type lastEvent struct {
	event PolicyEvent
	total int
}

func (h *lastEvent) Handle(event PolicyEvent, policyVersion uint64, policyDescription string, notes string) {
	h.event = event
	h.total++
}

// testPlugin is a Plugin that keeps track of the number of policies pushed to the plugin
type testPlugin struct {
	id              string
	appliedPolicies int
}

func (p *testPlugin) ID() string {
	return p.id
}

func (p *testPlugin) Apply(id string, data []byte) (bool, string) {
	p.appliedPolicies++
	return true, ""
}

func (p *testPlugin) Remove(id string) (bool, string) {
	p.appliedPolicies--
	return true, ""
}

func loadTestPolicyFile(path string) *policy.PolicyBundle {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Unable to read test policy file: %v", err))
	}
	return loadTestPolicy(bytes)
}

func loadTestPolicy(jsonPolicy []byte) *policy.PolicyBundle {
	bundle := &policy.PolicyBundle{}
	if err := json.Unmarshal(jsonPolicy, bundle); err != nil {
		panic(fmt.Sprintf("Unable to deserialize PolicyBundle: %v", err))
	}
	return bundle
}

// Controller API tests

func TestFetchOnFailure(t *testing.T) {
	st := store.LocalPolicyRepository{FilePath: "/dev/null"}
	invalid := NewEnforcer(&st, location, credentials)
	if bundle := invalid.Fetch(); bundle != nil {
		t.Fatal("Expected fetch to have failed on an invalid enforcer storage")
	}
}

func TestApplyAndFetch(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	if retrieved := e.Fetch(); retrieved.Description != bundle.Description {
		t.Fatalf("Expected current policy to be %v but was: %v", bundle, retrieved)
	}
}

func TestApplyNotifiesHandlers(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	h := &lastEvent{}
	e.RegisterHandler("h", h)

	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	if h.total != 1 {
		t.Fatalf("Expected one captured event but found: %v", h.total)
	}
	if h.event != PolicyApply {
		t.Fatalf("Expected a PolicyApply event but found: %v", h.event)
	}
}

func TestApplyFailureNotifiesHandlers(t *testing.T) {
	// invalidStore to force a failure in Apply()
	invalidStore := store.LocalPolicyRepository{FilePath: "/unexisting/path.json"}
	e := NewEnforcer(&invalidStore, location, credentials)
	h := &lastEvent{}
	e.RegisterHandler("h", h)

	if ok := e.Apply(bundle); ok {
		t.Fatal("Expected policy not to be applied to the enforcer")
	}

	if h.total != 1 {
		t.Fatalf("Expected one captured event but found: %v", h.total)
	}
	if h.event != PolicyApplyError {
		t.Fatalf("Expected a PolicyApplyError event but found: %v", h.event)
	}
}

func TestRegisterHandler(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	handler := lastEvent{}
	if registered := e.RegisterHandler("h", &handler); !registered {
		t.Fatal("Expected handler to be registered")
	}

	if _, ok := e.Handlers["h"]; !ok {
		t.Fatal("Expected handler to be present in the enforcer map")
	}

	// Duplicated IDs are not permitted
	if registered := e.RegisterHandler("h", &lastEvent{}); registered {
		t.Fatal("Duplicate IDs should not be allowed")
	}

	e.UnregisterHandler("h")
	if _, ok := e.Handlers["h"]; ok {
		t.Fatal("Expected handler to not be present in the enforcer map")
	}
}

func TestPlugins(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if l := len(e.Plugins()); l != 0 {
		t.Fatalf("Expected plugins to be empty, but found: %v", l)
	}

	plugin := testPlugin{id: "dummy", appliedPolicies: 5}
	e.RegisteredPlugins["dummy"] = &loadedPlugin{&plugin, true}

	plugins := e.Plugins()
	if l := len(plugins); l != 1 {
		t.Fatalf("Expected one plugin but found: %v", l)
	}
	if plugins[0] != plugin.ID() {
		t.Fatalf("Expected plugin to be: %v", plugin)
	}
}

func TestEnableNonRegisteredPlugin(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if enabled := e.Enable("unexisting"); enabled {
		t.Fatal("Plugin is not registered but has been enabled")
	}
}

func TestEnableAlreadyEnabledPlugin(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	plugin := testPlugin{id: "test_plugin", appliedPolicies: 0}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, true}

	if enabled := e.Enable(plugin.ID()); enabled {
		t.Fatal("Plugin has been enabled despite being already enabled")
	}
}

func TestEnablePlugin(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: 0}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, false}

	if enabled := e.Enable(plugin.ID()); !enabled {
		t.Fatal("Expected the plugin to be enabled")
	}

	if plugin.appliedPolicies != pluginPolicies {
		t.Fatalf("Expected %v to be applied after enabling but found: %v", pluginPolicies, plugin.appliedPolicies)
	}
}

func TestEnablePluginWhenNoPluginSpecificPolicies(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "no_policies", appliedPolicies: 0}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, false}

	if enabled := e.Enable(plugin.ID()); !enabled {
		t.Fatal("Expected the plugin to be enabled")
	}

	if plugin.appliedPolicies != 0 {
		t.Fatalf("Expected no policies to be applied after enabling but found: %v", plugin.appliedPolicies)
	}
}

func TestEnablePluginNoPoliciesInEnforcer(t *testing.T) {
	// invalidStore to force a failure in Fetch()
	invalidStore := store.LocalPolicyRepository{FilePath: "/dev/null"}
	e := NewEnforcer(&invalidStore, location, credentials)

	plugin := testPlugin{id: "no_policies", appliedPolicies: 5}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, false}

	if enabled := e.Enable(plugin.ID()); enabled {
		t.Fatal("Expected the plugin to not be enabled if policies could not be loaded")
	}
}

func TestDisableNonRegisteredPlugin(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if disabled := e.Disable("unexisting"); disabled {
		t.Fatal("Plugin is not registered but has been disabled")
	}
}

func TestDisableAlreadyDisabledPlugin(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	plugin := testPlugin{id: "test_plugin", appliedPolicies: 0}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, false}

	if disabled := e.Disable(plugin.ID()); disabled {
		t.Fatal("Plugin has been disabled despite being already disabled")
	}
}

func TestDisablePlugin(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: pluginPolicies}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, true}

	if disabled := e.Disable(plugin.ID()); !disabled {
		t.Fatal("Expected the plugin to be disabled")
	}

	if plugin.appliedPolicies != 0 {
		t.Fatalf("Expected %v to be removed after disabling but only %v were removed",
			pluginPolicies, pluginPolicies-plugin.appliedPolicies)
	}
}

func TestDisablePluginWhenNoPluginSpecificPolicies(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "no_policies", appliedPolicies: 5}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, true}

	if disabled := e.Disable(plugin.ID()); !disabled {
		t.Fatal("Expected the plugin to be disabled")
	}

	if plugin.appliedPolicies != 5 {
		t.Fatalf("Expected no policies to be removed after disabling but %v were removed",
			5-plugin.appliedPolicies)
	}
}

func TestDisablePluginNoPoliciesInEnforcer(t *testing.T) {
	// invalidStore to force a failure in Fetch()
	invalidStore := store.LocalPolicyRepository{FilePath: "/dev/null"}
	e := NewEnforcer(&invalidStore, location, credentials)

	plugin := testPlugin{id: "no_policies", appliedPolicies: 5}
	e.RegisteredPlugins[plugin.ID()] = &loadedPlugin{&plugin, true}

	if disabled := e.Disable(plugin.ID()); disabled {
		t.Fatal("Expected the plugin to not be disabled if policies could not be loaded")
	}
}

// Plugin API tests

func TestRegisterPlugin(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: 0}
	if registered := e.RegisterPlugin(&plugin); !registered {
		t.Fatal("Expected the plugin to be registered")
	}

	if plugin.appliedPolicies != pluginPolicies {
		t.Fatalf("Expected %v to be applied but found: %v", pluginPolicies, plugin.appliedPolicies)
	}
}

func TestRegisterDuplicatedPlugin(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: 0}
	e.RegisteredPlugins["vendor_plugin"] = &loadedPlugin{&plugin, true}

	if registered := e.RegisterPlugin(&plugin); registered {
		t.Fatal("Expected the duplicated plugin to not be registered")
	}
}

func TestRegisterPluginWithoutPolicies(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	noPolicies := testPlugin{id: "no_policies", appliedPolicies: 0}
	if registered := e.RegisterPlugin(&noPolicies); !registered {
		t.Fatal("Expected the plugin to be registered")
	}

	if noPolicies.appliedPolicies > 0 {
		t.Fatalf("Expected no policies to be applied but found: %v", noPolicies.appliedPolicies)
	}
}

func TestUnregisterPlugin(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	plugin := testPlugin{id: "vendor_plugin", appliedPolicies: pluginPolicies}
	e.RegisteredPlugins["vendor_plugin"] = &loadedPlugin{&plugin, true}
	if unregistered := e.UnregisterPlugin(&plugin); !unregistered {
		t.Fatal("Expected the plugin to be unregistered")
	}

	if plugin.appliedPolicies > 0 {
		t.Fatalf("Expected plugin to have no policies but found: %v", plugin.appliedPolicies)
	}
}

func TestUnregisterPluginWithoutPolicies(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if ok := e.Apply(bundle); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	noPolicies := testPlugin{id: "no_policies", appliedPolicies: 5}
	e.RegisteredPlugins["no_policies"] = &loadedPlugin{&noPolicies, true}
	if unregistered := e.UnregisterPlugin(&noPolicies); !unregistered {
		t.Fatal("Expected the plugin to be unregistered")
	}

	if noPolicies.appliedPolicies != 5 {
		t.Fatalf("Expected plugin policies to be unchanged but %v were removed", 5-noPolicies.appliedPolicies)
	}
}

func TestUnregisterUnexistingPlugin(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	if unregistered := e.UnregisterPlugin(&testPlugin{id: "unexisting"}); unregistered {
		t.Fatal("Expected the plugin to not be unregistered")
	}
}

// Request Level Answer API tests

// matchingPolicy configures the target with the Enforcer's IP address, location and credentials  so it can accept
// the request and allows access to a web service
var matchingPolicy = `
{
  "format_version": 1,
  "policy_version": 2,
  "description": "Matching bundle",
  "policies": [
    {
      "uuid": "46489674-5a07-40f9-9a43-7a7d08fa307e",
      "format_version": 0,
      "policy_version": 0,
      "description": "",
      "target": {
        "rules": {
          "op": "AND",
          "left": {
            "op": "AND",
            "left": { "op": "NONE", "rule": { "layer": "network", "layer_type": "ip", "pattern": "destIp=127.0.0.1" } },
            "right": { "op": "NONE", "rule": { "layer": "network", "layer_type": "tcp", "pattern": "destPort=80" } }
          },
          "right": { "op": "NONE", "rule": { "layer": "service", "layer_type": "www", "pattern": "service=/home" } }
        },
        "identified_by": { "name": "PADME", "value": "PADME" }
      },
      "allowed": [
        {
          "rules": {
            "op": "AND",
            "left": { "op": "NONE", "rule": { "layer": "network", "layer_type": "ip", "pattern": "srcIp=192.168.0.5" } },
            "right": { "op": "NONE", "rule": { "layer": "service", "layer_type": "www", "pattern": "service=/home" } } 
           },
          "identified_by": { "name": "PADME", "value": "PADME" }
        }
      ],
      "disallowed": [  ],
      "timeline": { "start": "0000-01-01T00:00:00Z", "end": "3000-01-01T00:00:00Z" },
      "rate": 0,
      "location": { "name": "PADME" },
      "contents": [ ],
      "signature": ""
    }
  ]
}`

func TestAnswerOKForMatchingPolicy(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	testPolicy := loadTestPolicy([]byte(matchingPolicy))
	if ok := e.Apply(testPolicy); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	request := []*policy.Rule{
		&policy.Rule{Layer: "network", LType: "ip", Pattern: "srcIp=192.168.0.5"},
		&policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=10.0.0.2"},
		&policy.Rule{Layer: "network", LType: "tcp", Pattern: "srcPort=5431"},
		&policy.Rule{Layer: "network", LType: "tcp", Pattern: "destPort=80"},
		&policy.Rule{Layer: "service", LType: "www", Pattern: "service=/home"},
	}

	if !e.Answer(request, credentials) {
		t.Fatalf("Expected policy %v to have allowed the request %v", testPolicy, request)
	}
}

// invalidPolicy configures a matching policy but in an already expired timeframe so the enforcer
// cannot consider it
var invalidPolicy = `
{
  "format_version": 1,
  "policy_version": 2,
  "description": "Matching bundle",
  "policies": [
    {
      "uuid": "46489674-5a07-40f9-9a43-7a7d08fa307e",
      "format_version": 0,
      "policy_version": 0,
      "description": "",
      "target": {
        "rules": {
          "op": "AND",
          "left": {
            "op": "AND",
            "left": { "op": "NONE", "rule": { "layer": "network", "layer_type": "ip", "pattern": "destIp=127.0.0.1" } },
            "right": { "op": "NONE", "rule": { "layer": "network", "layer_type": "tcp", "pattern": "destPort=80" } }
          },
          "right": { "op": "NONE", "rule": { "layer": "service", "layer_type": "www", "pattern": "service=/home" } }
        },
        "identified_by": { "name": "PADME", "value": "PADME" }
      },
      "allowed": [
        {
          "rules": {
            "op": "AND",
            "left": { "op": "NONE", "rule": { "layer": "network", "layer_type": "ip", "pattern": "srcIp=192.168.0.5" } },
            "right": { "op": "NONE", "rule": { "layer": "service", "layer_type": "www", "pattern": "service=/home" } } 
           },
          "identified_by": { "name": "PADME", "value": "PADME" }
        }
      ],
      "disallowed": [  ],
      "timeline": { "start": "0000-01-01T00:00:00Z", "end": "0000-01-02T00:00:00Z" },
      "rate": 0,
      "location": { "name": "PADME" },
      "contents": [ ],
      "signature": ""
    }
  ]
}`

func TestAnswerNOKForInvalidPolicy(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	testPolicy := loadTestPolicy([]byte(invalidPolicy))
	if ok := e.Apply(testPolicy); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	request := []*policy.Rule{
		&policy.Rule{Layer: "network", LType: "ip", Pattern: "srcIp=192.168.0.5"},
		&policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=10.0.0.2"},
		&policy.Rule{Layer: "network", LType: "tcp", Pattern: "srcPort=5431"},
		&policy.Rule{Layer: "network", LType: "tcp", Pattern: "destPort=80"},
		&policy.Rule{Layer: "service", LType: "www", Pattern: "service=/home"},
	}

	if e.Answer(request, credentials) {
		t.Fatalf("Expected policy %v to have rejected the request %v", testPolicy, request)
	}
}

// notAcceptedLocationPolicy configures a policy that is not accepted for being configured to a different location
var notAcceptedLocationPolicy = `
{
  "format_version": 1,
  "policy_version": 2,
  "description": "Matching bundle",
  "policies": [
    {
      "uuid": "46489674-5a07-40f9-9a43-7a7d08fa307e",
      "format_version": 0,
      "policy_version": 0,
      "description": "",
      "target": {
        "rules": {
          "op": "AND",
          "left": {
            "op": "AND",
            "left": { "op": "NONE", "rule": { "layer": "network", "layer_type": "ip", "pattern": "destIp=127.0.0.1" } },
            "right": { "op": "NONE", "rule": { "layer": "network", "layer_type": "tcp", "pattern": "destPort=80" } }
          },
          "right": { "op": "NONE", "rule": { "layer": "service", "layer_type": "www", "pattern": "service=/home" } }
        },
        "identified_by": { "name": "PADME", "value": "PADME" }
      },
      "allowed": [  ],
      "disallowed": [  ],
      "timeline": { "start": "0000-01-01T00:00:00Z", "end": "3000-01-01T00:00:00Z" },
      "rate": 0,
      "location": { "name": "somewhere else" },
      "contents": [ ],
      "signature": ""
    }
  ]
}`

func TestAnswerOKForNotAcceptedLocationPolicy(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	testPolicy := loadTestPolicy([]byte(notAcceptedLocationPolicy))
	if ok := e.Apply(testPolicy); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	request := []*policy.Rule{
		&policy.Rule{Layer: "network", LType: "ip", Pattern: "srcIp=192.168.0.5"},
		&policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=10.0.0.2"},
		&policy.Rule{Layer: "network", LType: "tcp", Pattern: "srcPort=5431"},
		&policy.Rule{Layer: "network", LType: "tcp", Pattern: "destPort=80"},
		&policy.Rule{Layer: "service", LType: "www", Pattern: "service=/home"},
	}

	if !e.Answer(request, credentials) {
		t.Fatalf("Expected policy %v to have accepted the request %v", testPolicy, request)
	}
}

// notAcceptedTargetPolicy configures a policy that is not accepted for being configured for a different target
var notAcceptedTargetPolicy = `
{
  "format_version": 1,
  "policy_version": 2,
  "description": "Matching bundle",
  "policies": [
    {
      "uuid": "46489674-5a07-40f9-9a43-7a7d08fa307e",
      "format_version": 0,
      "policy_version": 0,
      "description": "",
      "target": {
        "rules": {
          "op": "AND",
          "left": {
            "op": "AND",
            "left": { "op": "NONE", "rule": { "layer": "network", "layer_type": "ip", "pattern": "destIp=80.80.80.80" } },
            "right": { "op": "NONE", "rule": { "layer": "network", "layer_type": "tcp", "pattern": "destPort=80" } }
          },
          "right": { "op": "NONE", "rule": { "layer": "service", "layer_type": "www", "pattern": "service=/home" } }
        },
        "identified_by": { "name": "PADME", "value": "PADME" }
      },
      "allowed": [  ],
      "disallowed": [  ],
      "timeline": { "start": "0000-01-01T00:00:00Z", "end": "3000-01-01T00:00:00Z" },
      "rate": 0,
      "location": { "name": "PADME" },
      "contents": [ ],
      "signature": ""
    }
  ]
}`

func TestAnswerOKForNotAcceptedTargetPolicy(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	testPolicy := loadTestPolicy([]byte(notAcceptedTargetPolicy))
	if ok := e.Apply(testPolicy); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	request := []*policy.Rule{
		&policy.Rule{Layer: "network", LType: "ip", Pattern: "srcIp=192.168.0.5"},
		&policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=10.0.0.2"},
		&policy.Rule{Layer: "network", LType: "tcp", Pattern: "srcPort=5431"},
		&policy.Rule{Layer: "network", LType: "tcp", Pattern: "destPort=80"},
		&policy.Rule{Layer: "service", LType: "www", Pattern: "service=/home"},
	}

	if !e.Answer(request, credentials) {
		t.Fatalf("Expected policy %v to have accepted the request %v", testPolicy, request)
	}
}

// acceptednotAllowedPolicy configures a valid policy for this enforcer that does not allow access to the
// requested web servic (it allows a different source ip address)e
var acceptedNotAllowedPolicy = `
{
  "format_version": 1,
  "policy_version": 2,
  "description": "Matching bundle",
  "policies": [
    {
      "uuid": "46489674-5a07-40f9-9a43-7a7d08fa307e",
      "format_version": 0,
      "policy_version": 0,
      "description": "",
      "target": {
        "rules": {
          "op": "AND",
          "left": {
            "op": "AND",
            "left": { "op": "NONE", "rule": { "layer": "network", "layer_type": "ip", "pattern": "destIp=127.0.0.1" } },
            "right": { "op": "NONE", "rule": { "layer": "network", "layer_type": "tcp", "pattern": "destPort=80" } }
          },
          "right": { "op": "NONE", "rule": { "layer": "service", "layer_type": "www", "pattern": "service=/home" } }
        },
        "identified_by": { "name": "PADME", "value": "PADME" }
      },
      "allowed": [
        {
          "rules": {
            "op": "AND",
            "left": { "op": "NONE", "rule": { "layer": "network", "layer_type": "ip", "pattern": "srcIp=192.168.0.7" } },
            "right": { "op": "NONE", "rule": { "layer": "service", "layer_type": "www", "pattern": "service=/home" } } 
           },
          "identified_by": { "name": "PADME", "value": "PADME" }
        }
      ],
      "disallowed": [  ],
      "timeline": { "start": "0000-01-01T00:00:00Z", "end": "3000-01-01T00:00:00Z" },
      "rate": 0,
      "location": { "name": "PADME" },
      "contents": [ ],
      "signature": ""
    }
  ]
}`

func TestAnswerNOKForNotAllowedPolicy(t *testing.T) {
	e := NewEnforcer(&testStore, location, credentials)
	testPolicy := loadTestPolicy([]byte(acceptedNotAllowedPolicy))
	if ok := e.Apply(testPolicy); !ok {
		t.Fatal("Expected policy to be applied to the enforcer")
	}

	request := []*policy.Rule{
		&policy.Rule{Layer: "network", LType: "ip", Pattern: "srcIp=192.168.0.5"},
		&policy.Rule{Layer: "network", LType: "ip", Pattern: "destIp=10.0.0.2"},
		&policy.Rule{Layer: "network", LType: "tcp", Pattern: "srcPort=5431"},
		&policy.Rule{Layer: "network", LType: "tcp", Pattern: "destPort=80"},
		&policy.Rule{Layer: "service", LType: "www", Pattern: "service=/home"},
	}

	if e.Answer(request, credentials) {
		t.Fatalf("Expected policy %v to have rejected the request %v", testPolicy, request)
	}
}
