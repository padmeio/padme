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

// Package filesystem defines storage repositories for the local filesystem.
//
// Policies and information about the existing plugins are stored in plain
// file sin the local filesystem.
package filesystem

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/padmeio/padme/policy"
)

// LocalPolicyRepository persists the policies in a file in the local filesystem
type LocalPolicyRepository struct {
	FilePath string
}

// Save serializes the given PolicyBundle and stores it in the filesystem
func (store *LocalPolicyRepository) Save(bundle *policy.PolicyBundle) error {
	bytes, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(store.FilePath, bytes, 0644)
}

// Get reads the current PolicyBundle from the filesystem and returns it
func (store *LocalPolicyRepository) Get() (*policy.PolicyBundle, error) {
	bytes, err := ioutil.ReadFile(store.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return nil, err
	}
	bundle := &policy.PolicyBundle{}
	if err = json.Unmarshal(bytes, bundle); err != nil {
		return nil, err
	}
	return bundle, nil
}
