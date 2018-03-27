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

// Package enforcer contains the PADME Enforcer definition. See relevant docs.
//
// This package defines the different enforcer APIs and provides interfaces to
// convert any request into a PADME Resource so it can be evaluated against the
// policies known to the enforcer.
package enforcer

import (
	"github.com/padmeio/padme/enforcer/plugins"
	"github.com/padmeio/padme/policy"
)

// PacketAnswerAPI defines the Packet Level Answer API. It supports infrequent low level
// look ups such as those that might be found in software defined networking.
type PacketAnswerAPI interface {

	// Answer inspects a packet, extracts any protocol information that it can
	// from the packet, and matches it against policies known by the enforcer.
	//
	// true is returned if policies allow this traffic.
	// false is returned if policies do not allow this traffic, or if the packet was not understood.
	Answer(packet []byte) bool
}

// RequestAnswerAPI defines the Request Level Answer API. It supports most normal services requests.
// For example a web services request for a specific target URL uses this call.
type RequestAnswerAPI interface {

	// Answer matches a request described by properties and credential
	// against the rules known by this enforcer.
	//
	// properties are the intrinsic properties of a given request. For
	// example the source tcp port or the destination ip address, or the
	// target URI. These are composed (along with the credential)
	// into a resource object. Composition of the properties is done
	// using an AND operation.
	//
	// Care must be taken in this API to ensure that standard
	// values for Layer and LType are readily available.
	//
	// No wild carding is permitted in a request.
	//
	// true is returned if policies allow this request.
	// false is returned if policies do not allow this request.
	Answer(properties []*policy.Rule, credential *policy.Credential) bool
}

// PluginAPI  is used to configure sub-components that enforce policies on behalf of the Enforcer.
type PluginAPI interface {

	// Register the specified plugin with the enforcer.  Only one
	// plugin with a specified id may be registered with an enforcer
	// at a time. If a plugin could not be registered it should
	// not attempt enforcement actions.
	//
	// Upon registration of a new plugin, assuming the plugin
	// is enabled, all policies are evaluated and any that control
	// this plugin apply themselves to this plugin.
	//
	// Parameters:
	//	    plugin - the plugin object used to control this plugin
	//
	// Returns:
	//	    true - the plugin was successfully registered
	//	    false - the plugin could not be registered
	RegisterPlugin(plugin plugins.Plugin) bool

	// Unregister a plugin from the enforcer. When this occurs
	// all applied policies are removed.
	//
	// Parameters:
	//	    plugin - the plugin object used to control this plugin
	//
	// Returns:
	//	    true - the plugin was successfully unregistered
	//	    false - the plugin was not successfully unregistered.
	UnregisterPlugin(plugin plugins.Plugin) bool
}

// PolicyEvent defines events that can be notified to controllers upon policy operations
// on the enforcer
type PolicyEvent int

const (
	// PolicyApply event is fired when a policy is applied.
	// for example if a plugin was added/enabled, or if its start time passed.
	PolicyApply = PolicyEvent(iota)

	// PolicyApplyError event is fired when attempt to apply a policy failed.
	PolicyApplyError

	// PolicyRemove event is fired when  policy is removed.
	// For example if a plugin was removed or the end time of a policy passed.
	PolicyRemove

	// PolicyRemoveError event is fired when An attempt to remove a policy failed.
	PolicyRemoveError
)

// PolicyEventHandler defines the interface Controllers are expected to implement to be notified
// of events occurring on policies.
type PolicyEventHandler interface {

	// Handle is called when an event occurs on a policy
	// the version and description of the policy are passed to
	// the controller.  An optional notes field
	// is used to carry the error string in the event of
	// a PLUGIN_APPLY_ERROR or PLUGIN_REMOVE_ERROR
	//
	// Parameters:
	//	event - the event
	//	policyVersion - the version of the policy that was effected
	//	policyDescription - the description of the policy that was effected
	//	notes - an error description or empty
	Handle(event PolicyEvent, policyVersion uint64, policyDescription string, notes string)
}

// ControllerAPI defines interactions between an Enforcer and a Controller.
// Controller/Enforcer discovery is presently not covered here.  Mutual knowledge
// is assumed.  This API is also agnostic as to whether or not push or pull is
// used between the Enforcer and Controller.
type ControllerAPI interface {

	// Register a controller with this enforcer for notifications of events
	//
	// The controller must specify an id by which it will be known to this enforcer.
	// this id must be unique among controllers.
	//
	// Parameters:
	//	    id - the controller id
	//	    handler - the handler which is to be called when an event occurs.
	//
	// Returns:
	//	    true - registration succeeded
	//	    false - registration failed
	RegisterHandler(id string, handler PolicyEventHandler) bool

	// Unregister remoes remove the registration of a controller with this enforcer.
	//
	// Unlike plugins the unregistration of a control does not
	// effect the state of policies installed on this enforcer.
	// Simply, events that might have been reported to unregistered
	// controller are simply lost.
	//
	// Parameters:
	//	    id - the id of a previously registered controller
	UnregisterHandler(id string)

	// Apply a policy bundle to the enforcer.
	//
	// Policies are specifically ordered. Thus the addition, removal, or
	// modification of one or more policy requires a new policy bundle to
	// be applied to the enforcer. The controller is responsible for
	// determining which policies have been added or removed and
	// modifying its state or the state of its plugins as necessary.
	// If no PolicyVersions change, and no policies are added
	// or removed, then nothing is done.
	//
	// A return code is provided, however failures for individual policies
	// are returned via the PolicyEventHandler.
	//
	// Rollback is achieved by shipping an old policy bundle with higher
	// version numbers.
	//
	// Parameters:
	//	    bundle - the policy bundle to apply
	//
	// Return:
	//	    true - all policies were applied
	//	    false - some polices were not applied, see PolicyEventHandler for specific issues
	Apply(bundle *policy.PolicyBundle) bool

	// Fetch retrieves the current policy bundle from this enforcer
	Fetch() *policy.PolicyBundle

	// Plugins returns a list of all the plugins supported by this enforcer.
	Plugins() []string

	// Enable explicitly enables a particular plugin.
	//
	// If the plugin is already registered then this causes
	// it to become enabled and causes all policies that
	// use this plugin to be applied. If the plugin is
	// not registered then when it registers it automatically
	// becomes enabled.
	//
	// Specific errors encountered during the application of
	// policies are returned via the PolicyEventHandler
	//
	// Parameters:
	//	    pluginID - the id of the specific plugin
	//
	// Returns:
	//	    true - the plugin was enabled
	//	    false - the plugin could not be enabled
	Enable(pluginID string) bool

	// Disable explicitly disables a particular plugin.
	//
	// If the plugin is already registered, then all policies
	// operating through it are removed from the plugin.
	// If the plugin is not registered then the decision
	// is remembered and it must be explicitly enabled
	// before operating again.
	//
	// Specific errors encountered during the removal of
	// policies are returned via the PolicyEventHandler
	//
	// Specific errors encountered during the application of
	// policies are returned via the PolicyEventHandler
	//
	// Parameters:
	//	    pluginID - the id of the specific plugin
	//
	// Returns:
	//	    true - the plugin was disabled
	//	    false - the plugin could not be disabled
	Disable(pluginID string) bool
}
