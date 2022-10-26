// Copyright 2021 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package note provides some helpers for instantiating note-compatible
// signers and verifiers.
package note

import (
	"github.com/google/trillian-examples/formats/log"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/golang/glog"

	sdb_note "golang.org/x/mod/sumdb/note"
)

// Get the contents of key file f.
func getKeyFile(f string) ([]byte, error) {
	k, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	return k, nil
}

// Get key material either by reading it from file f, or if f is the empty string, by getting
// the key material directly from the environment variable env. t is a string indicating
// the type of key ("public" or "private"), and op is name the command-line option for
// supplying the keyfile (like "--public_key"). t and op are used only for error messages.
//
// Returns the key material, the key identifier, and an error.
func getKeyMaterial(f string, t string, op string, env string) ([]byte, string, error) {
	var k []byte
	var err error
	if len(f) > 0 {
		k, err = getKeyFile(f)
		if err != nil {
			return nil, "", err
		}
	} else {
		k = []byte(os.Getenv(env))
		if len(k) == 0 {
			glog.Exitf("Supply %s key file path using %s or set %s environment variable", t, op, env)
		}
	}
	return k, log.ID("", k), nil
}

// Returns a sumdb.note.Verifier and the ID of the public key. The ID is typically the
// sha256 sum of the public key material. In the future, for externally managed keys, the
// key ID may be something else.
//
// Attempts to read key material from f, or uses the SERVERLESS_LOG_PUBLIC_KEY
// env var if f is unset.
func NewVerifierWithKeyID(f string, op string) (sdb_note.Verifier, string, error) {
	k, id, err := getKeyMaterial(f, "public", op, "SERVERLESS_LOG_PUBLIC_KEY")
	if err != nil {
		return nil, "", err
	}
	
	v, err := sdb_note.NewVerifier(string(k))
	if err != nil {
		return nil, "", err
	}
	return v, id, nil
}

// This function does the same thing as NewVerifierWithKey, but doesn't return the key bytes.
func NewVerifier(f string, name string) (sdb_note.Verifier, error) {
	v, _, err := NewVerifierWithKeyID(f, name)
	return v, err
}


// Returns a sumdb.note.Signer, with the private key coming from either the specified
// file or if privKeyFile is the empty string, the value in the environment variable
// SERVERLESS_LOG_PRIVATE_KEY.
func NewSigner(f string, op string) (sdb_note.Signer, error) {
	k, _, err := getKeyMaterial(f, "private", op, "SERVERLESS_LOG_PRIVATE_KEY")
	if err != nil {
		return nil, err
	}

	return sdb_note.NewSigner(string(k))
}
