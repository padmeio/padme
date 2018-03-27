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

// Package store configures Enforcer persistence.
//
// Enforcers use a policy repository to store the policies they
// manage, and to persist information about the existing plugins
// and their status (enabled, disabled).
package store

import (
	"github.com/padmeio/padme/policy"
)

// PolicyRepository defines how policies are stored by this enforcer
type PolicyRepository interface {

	// Save stores the given PolicyBundle
	Save(bundle *policy.PolicyBundle) error

	// Get retrieves the PolicyBundle for this enforcer
	Get() (*policy.PolicyBundle, error)
}
