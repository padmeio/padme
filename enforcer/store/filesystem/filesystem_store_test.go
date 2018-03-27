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

package filesystem

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/padmeio/padme/policy"
)

var (
	testFile = fmt.Sprintf("%v/src/github.com/padmeio/padme/policy/test_policy.json", os.Getenv("GOPATH"))
	store    = LocalPolicyRepository{FilePath: "/tmp/padme-enforcer.json"}
)

func loadTestPolicy(path string) *policy.PolicyBundle {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("Unable to read test policy file: %v", err))
	}
	bundle := &policy.PolicyBundle{}
	if err = json.Unmarshal(bytes, bundle); err != nil {
		panic(fmt.Sprintf("Unable to deserialize PolicyBundle: %v", err))
	}
	return bundle
}

func TestFileSystemPolicyStore(t *testing.T) {
	bundle := loadTestPolicy(testFile)
	if err := store.Save(bundle); err != nil {
		t.Errorf("Could not persist policy bundle: %v", err)
	}

	reloaded, err := store.Get()
	if err != nil {
		t.Errorf("Could not read the policy from the policy store: %v", err)
	}

	if bundle.Description != reloaded.Description || len(bundle.Policies) != len(reloaded.Policies) {
		t.Errorf("The persisted policy and the loaded one differ: %v %v", bundle, reloaded)
	}
}
