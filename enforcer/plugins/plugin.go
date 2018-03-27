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

// Package plugins defines how Enforcer plugins are configured and loaded in PADME.
package plugins

// Plugin defines the Plugin interface is implemented by or on behalf of an external
// Policy enforcement component. There can only be one
// plugin with a given id on any given enforcer, and this id must
// be consistent throughout the zone.
//
// Policies that have a non-empty CContents apply use this interface
// to configure the specified plugin.
//
// As there is no guarantee that the sub-component understands time.
// A policy is not applied to the plugin until the start time in
// its Duration field. It is unapplied at the end time.  This
// must be taken into account when testing policies.
//
// Registered, Unregistered, Enabled, Disabled.
//
// Plugins register themselves with the enforcer when they
// are ready to operate and unregister themselves when
// they are no longer able or willing to operate. Additionally
// controllers can instruct enforcers to ignore certain
// plugins by disabling them.
//
// By default specific plugins are disabled.
type Plugin interface {

	// ID returns the unique id of this plugin in the zone
	ID() string

	// Apply appies the policy information provided by a policy
	//
	// Parameters:
	//	id - an identified asserted by the enforcer through which subsequent operations regarding this policy.
	//	data - the Blob specified in the Contents part of the Policy
	//
	// return (bool, error)
	//	true - the policy was applied
	//	false - the policy was not applied
	//	string - a human readable error returned by the plugin. valid if false is returned.
	Apply(id string, data []byte) (bool, string)

	// Remove removes a policy that was previously applied
	//
	// Parameters:
	//	id - the id asserted when the policy was applied
	//
	// return (bool, error)
	//	true - the policy was removed, or did not exist
	//	false - the policy was not removed
	//	string - a human readable error returned by the plugin. valid if false is returned.
	Remove(id string) (bool, string)
}

// PluginLoader is the type responsible of loading and unloading plugins
type PluginLoader interface {

	// Load a plugin given its ID
	Load(id string) (Plugin, error)

	// u¡Unload the given plugin and free any associated resources
	Unload(id string) error
}
