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

package main

import (
	"encoding/base64"
	"log"
)

// DummyPlugin just logs the plugin operations
// It implements the Enforcer plugins.Plugin interface
type DummyPlugin struct {
	// Name is the name of the plugin
	Name string
}

// Dummy is the exported plugin. The convention of the NativePluginLoader is that the
// name of the exported plugin variable must be the capitalized name of the plugin.
var Dummy = DummyPlugin{Name: "dummy"}

// ID returns the name of this plugin
func (p DummyPlugin) ID() string {
	return p.Name
}

// Apply applies the policy data (just logs it)
func (p DummyPlugin) Apply(id string, data []byte) (bool, string) {
	log.Printf("Applying policy %v with data: %v", id, base64.StdEncoding.EncodeToString(data))
	return true, ""
}

// Remove removes all applied policy data (just logs the operation
func (p DummyPlugin) Remove(id string) (bool, string) {
	log.Printf("Removing policy %v...", id)
	return true, ""
}
