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

// Package main provides a command line tool for sequencing entries in
// a serverless log.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/fortanix/sdkms-client-go/sdkms"
	"github.com/golang/glog"
	"github.com/google/trillian-examples/serverless/internal/storage/fs"
	"github.com/google/trillian-examples/serverless/pkg/log"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"

	fmtlog "github.com/transparency-dev/formats/log"
)

var (
	storageDir  = flag.String("storage_dir", "", "Root directory to store log data.")
	initialise  = flag.Bool("initialise", false, "Set when creating a new log to initialise the structure.")
	pubKeyFile  = flag.String("public_key", "", "Location of public key file. If unset, uses the contents of the SERVERLESS_LOG_PUBLIC_KEY environment variable.")
	privKeyFile = flag.String("private_key", "", "Location of private key file. If unset, uses the contents of the SERVERLESS_LOG_PRIVATE_KEY environment variable.")
	origin      = flag.String("origin", "", "Log origin string to use in produced checkpoint.")
	dsmKeyId    = flag.String("dsm_key_id", "", "ID of key in DSM to use for signing")
	dsmApiKey   = flag.String("dsm_api_key", "", "API key for accessing smartkey")
	dsmEndpoint = flag.String("dsm_endpoint", "https://www.smartkey.io", "DSM instance to use when signing with DSM")
	pubKeyOut   = flag.String("public_key_out", "", "When initializing and using a DSM signing key, write the public key to this file")
	suspend     = flag.String("suspend", "", "Write state to a file and suspend signing if approval is required")
	resume      = flag.String("resume", "", "Resume signing after a previous signing attempt was suspended")
)

const Ed25519PubKeyLength = 32

// The saved state necessary to resume a signing request.
type QuorumSigningState struct {
	Msg []byte
	RequestID sdkms.UUID
}

// The keyHash implementation is copied from the Note keyHash implementation. This function is private to Note
// for no good reason. We want to use the same key hashing function because the key hashes are used internally
// by the Note package for identifying which keys were used to sign a Note.

// keyHash computes the key hash for the given server name and encoded public key.
func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}

// This type and associated functions implement the note.Signer signing interface, but sign using a key in DSM.
type dsmSigner struct {
	name string
	hash uint32
	client *sdkms.Client
	key *sdkms.SobjectDescriptor
}

func (signer *dsmSigner) Name() string {
	return signer.name
}

func (signer *dsmSigner) KeyHash() uint32 {
	return signer.hash
}

func (signer *dsmSigner) waitForApproval(status sdkms.ApprovalStatus, requestID sdkms.UUID) ([]byte, error) {
	ctx := context.Background()
	for status == sdkms.ApprovalStatusPending {
		glog.Info("Waiting for signing request to be approved...")
		time.Sleep(10 * time.Second)
		approvalRequest, err := signer.client.GetApprovalRequest(ctx, requestID)
		if err != nil {
			return nil, fmt.Errorf("GetApprovalRequest failed: %q", err)
		}
		status = approvalRequest.Status
	}
	switch status {
	case sdkms.ApprovalStatusApproved, sdkms.ApprovalStatusFailed:
		res, err := signer.client.GetApprovalRequestResult(ctx, requestID)
		if err != nil {
			return nil, fmt.Errorf("GetApprovalRequestResult failed: %q", err)
		}
		var signResp sdkms.SignResponse
		if err := res.Parse(&signResp); err != nil {
			return nil, fmt.Errorf("Parsing approval result failed: %q", err)
		}
		return signResp.Signature, nil
	default:
		return nil, fmt.Errorf("Bad approval status: %q", status)
	}
}

func (signer *dsmSigner) signWithApproval(request sdkms.SignRequest, msg []byte) ([]byte, error) {
	ctx := context.Background()
	description := "Integrate transparency log entries"
	approvalRequest, err := signer.client.RequestApprovalToSign(ctx, request, &description)
	if err != nil {
		return nil, fmt.Errorf("RequestApprovalToSign failed: %q", err)
	}

	if approvalRequest.Status == sdkms.ApprovalStatusPending && len(*suspend) != 0 {
		// Suspend on approval pending. Write some state to the suspend file so signing
		// can be resumed with another invocation of the tool.
		state := QuorumSigningState{
			Msg: msg,
			RequestID: approvalRequest.RequestID,
		}
		state_json, err := json.Marshal(state)
		if err != nil {
			return nil, fmt.Errorf("Unable to construct json signing state: %q", err)
		}
		if err := os.WriteFile(*suspend, state_json, 0644); err != nil {
			return nil, fmt.Errorf("Unable to write json signing state to file %s: %q",
				*suspend, err)
		}
		glog.Infof("Signing context written to %s", *suspend)
		glog.Infof("When signing is approved, rerun with --resume %s", *suspend)
		os.Exit(0)
	}		

	// Poll until request is approved.
	return signer.waitForApproval(approvalRequest.Status, approvalRequest.RequestID)
}

func (signer *dsmSigner) resumeSigning(msg []byte) ([]byte, error) {
	data, err := os.ReadFile(*resume)
	if err != nil {
		return nil, fmt.Errorf("Error reading resume file: %q", err)
	}
	var state QuorumSigningState
	err = json.Unmarshal(data, &state)
	if err != nil {
		return nil, fmt.Errorf("Error deserializing signing state from %s: %q", *resume, err)
	}
	// Check whether we still have the same log state that got signed. If we don't have the same state,
	// we can't proceed.
	if bytes.Compare(msg, state.Msg) != 0 {
		return nil, fmt.Errorf("Suspended state did not match current state. Expected %s got %s",
			string(state.Msg), string(msg))
	}
	approvalRequest, err := signer.client.GetApprovalRequest(context.Background(), state.RequestID)
	return signer.waitForApproval(approvalRequest.Status, state.RequestID)
}

func (signer *dsmSigner) Sign(msg []byte) ([]byte, error) {
	request := sdkms.SignRequest{
		Key: signer.key,
		HashAlg: sdkms.DigestAlgorithmSha512,
		Data: &msg,
	}
	
	if len(*resume) > 0 {
		// We're resuming a previously suspended request.
		return signer.resumeSigning(msg)
	}

	// First, we attempt without asking for approval. This may succeed if there is no quorum policy (and we
	// have appropriate permissions, the key exists and can be used for signing, etc.) If there is a quorum
	// policy, we'll get an error indicating that, and we'll retry with quorum approval.
	response, error := signer.client.Sign(context.Background(), request)
	if error == nil {
		return response.Signature, nil
	}
	if backendError, ok := error.(*sdkms.BackendError); ok {
		if backendError.Message == "This operation requires approval" {
			return signer.signWithApproval(request, msg)
		}
	}
	return nil, error
}

func main() {
	flag.Parse()
	ctx := context.Background()

	if len(*origin) == 0 {
		glog.Exitf("Please set --origin flag to log identifier.")
	}

	if len(*suspend) != 0 && len(*resume) != 0 {
		glog.Exitf("You must not specify both --suspend and --resume.")
	}

	h := rfc6962.DefaultHasher

	var verifier note.Verifier
	var signer note.Signer
	var err error

	verifier, signer, err = getKeys()
	if err != nil {
		glog.Exitf("%s", err)
	}
	var cpNote note.Note

	if *initialise {
		var st *fs.Storage
		if len(*resume) == 0 {
			st, err = fs.Create(*storageDir)
			if err != nil {
				glog.Exitf("Failed to create log: %q", err)
			}
		} else {
			st, err = fs.Load(*storageDir, 0)
			if err != nil {
				glog.Exitf("Failed to initialize log: %q", err)
			}
		}
		cp := fmtlog.Checkpoint{
			Hash: h.EmptyRoot(),
		}
		if err := signAndWrite(ctx, &cp, cpNote, signer, st); err != nil {
			glog.Exitf("Failed to sign: %q", err)
		}
		os.Exit(0)
	}

	// init storage
	cpRaw, err := fs.ReadCheckpoint(*storageDir)
	if err != nil {
		glog.Exitf("Failed to read log checkpoint: %q", err)
	}

	// Check signatures
	cp, _, _, err := fmtlog.ParseCheckpoint(cpRaw, *origin, verifier)
	if err != nil {
		glog.Exitf("Failed to open Checkpoint: %q", err)
	}
	st, err := fs.Load(*storageDir, cp.Size)
	if err != nil {
		glog.Exitf("Failed to load storage: %q", err)
	}

	// Integrate new entries
	newCp, err := log.Integrate(ctx, *cp, st, h)
	if err != nil {
		glog.Exitf("Failed to integrate: %q", err)
	}
	if newCp == nil {
		glog.Exit("Nothing to integrate")
	}

	err = signAndWrite(ctx, newCp, cpNote, signer, st)
	if err != nil {
		glog.Exitf("Failed to sign: %q", err)
	}
}

// Extracts the key's name (for golang Note purposes) from the key metadata. It is an error if the name field
// does not exist within the metadata. Note that this is separate from the key's actual name in DSM, which
// must be unique (within the account).
func getDsmKeyName(key *sdkms.Sobject) (string, error) {
	if key.CustomMetadata == nil {
		return "", fmt.Errorf("key had no custom metadata")
	}

	return (*key.CustomMetadata)["name"], nil
}

// Returns a Note.Verifier for a DSM signing key's public key. Since this is the public key, we can get the actual
// key material and verify signatures locally without using DSM.
func makeDsmVerifier(name string, key *sdkms.Sobject) (note.Verifier, uint32, error) {
	pubAny, err := x509.ParsePKIXPublicKey(*key.PubKey)

	pub := pubAny.(ed25519.PublicKey)
	if len(pub) != Ed25519PubKeyLength {
		return nil, 0,fmt.Errorf("Invalid key length for ed25519 public key. Expected %d, got %d",
			Ed25519PubKeyLength, len(pub))
	}

	// In Note format, the first byte of the key is the key algorithm. 1 indicates ed25519, which is the only
	// supported key type right now.
	pub = append([]byte{1}, pub...)
	
	pubKeyHash := keyHash(name, pub)
	
	// Unfortunately, the only provided interface to construct a standard Note verifier is via this formatted
	// string. The alternative here is creating our own Verifier-compatible type we could directly populate,
	// but that would involve essentially copying code from the Note implementation. It's simpler (if uglier)
	// to string-format the public key in the way expected by Note.
	keyString := fmt.Sprintf("%s+%08x+%s", name, pubKeyHash, base64.StdEncoding.EncodeToString(pub))

	// Write the public key to a file if requested.
	if len(*pubKeyOut) > 0 {
		err := writeFileIfNotExists(*pubKeyOut, keyString)
		if err != nil {
			return nil, 0, fmt.Errorf("Unable to write public key to %s: %q", *pubKeyOut, err)
		}
	}

	verifier, err := note.NewVerifier(keyString)
	if err != nil {
		return nil, 0, fmt.Errorf("Unable to construct note.Verifier: %q", err)
	}

	return verifier, pubKeyHash, nil
}

// Create a Note.Signer-compatible signer that will sign using a DSM key. Unlike with the Verifier, we have to
// construct our own Signer type that performs the signing in DSM.
func makeDsmSigner(client *sdkms.Client, name string, keyHash uint32, key *sdkms.SobjectDescriptor) *dsmSigner {
	return &dsmSigner{
		name: name,
		hash: keyHash,
		client: client,
		key: key,
	}
}

func getDsmKeys() (note.Verifier, note.Signer, error) {
	if len(*dsmApiKey) == 0 {
		return nil, nil, fmt.Errorf("When signing with DSM, --dsm_key_id and --dsm_api_key must both be provided")
	}

	if len(*dsmKeyId) == 0 {
		return nil, nil, fmt.Errorf("When signing with DSM, --dsm_key_id and --dsm_api_key must both be provided")
	}

	client := sdkms.Client{
		HTTPClient: http.DefaultClient,
		Auth: sdkms.APIKey(*dsmApiKey),
		Endpoint: *dsmEndpoint,
	}
	keyid := sdkms.SobjectDescriptor{
		Kid: dsmKeyId,
	}

	key, err := client.GetSobject(context.Background(), nil, keyid)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to get key details from DSM: %q", err)
	}

	// Check to see if the specified key is suitable.
	if key.ObjType != sdkms.ObjectTypeEc {
		return nil, nil, fmt.Errorf("DSM key was not an elliptic curve key")
	}

	if key.EllipticCurve == nil {
		return nil, nil, fmt.Errorf("DSM key did not have an elliptic curve type")
	}

	if *key.EllipticCurve != sdkms.EllipticCurveEd25519 {
		return nil, nil, fmt.Errorf("DSM key had incorrect elliptic curve type")
	}

	if key.KeyOps & sdkms.KeyOperationsSign == 0 {
		return nil, nil, fmt.Errorf("DSM key did not have Sign operation enabled")
	}

	name, err := getDsmKeyName(key)
	if err != nil {
		return nil, nil, err
	}

	verifier, pubKeyHash, err := makeDsmVerifier(name, key)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to construct verifier: %q", err)
	}

	signer := makeDsmSigner(&client, name, pubKeyHash, &keyid)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to construct signer: %q", err)
	}
	
	return verifier, signer, nil
}

// Returns Note-compatible Verifier and Signer, based on the requested key type (local or DSM).
func getKeys() (note.Verifier, note.Signer, error) {
	// DSM key requested.
	if len(*dsmKeyId) > 0 || len(*dsmApiKey) > 0 {
		return getDsmKeys()
	}

	// Non-DSM keys. Read log public key from file or environment variable
	var pubKey string
	var err error
	if len(*pubKeyFile) > 0 {
		pubKey, err = getKeyFile(*pubKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to get public key: %q", err)
		}
	} else {
		pubKey = os.Getenv("SERVERLESS_LOG_PUBLIC_KEY")
		if len(pubKey) == 0 {
			return nil, nil, fmt.Errorf("Supply public key file path using --public_key or set SERVERLESS_LOG_PUBLIC_KEY environment variable")
		}
	}
	verifier, err := note.NewVerifier(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to instantiate Verifier: %q", err)
	}
	
	// Read log private key from file or environment variable
	var privKey string
	if len(*privKeyFile) > 0 {
		privKey, err = getKeyFile(*privKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("Unable to get private key: %q", err)
		}
	} else {
		privKey = os.Getenv("SERVERLESS_LOG_PRIVATE_KEY")
		if len(privKey) == 0 {
			return nil, nil, fmt.Errorf("Supply private key file path using --private_key or set SERVERLESS_LOG_PUBLIC_KEY environment variable")
		}
	}

	s, err := note.NewSigner(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to instantiate signer: %q", err)
	}

	return verifier, s, nil
}

func getKeyFile(path string) (string, error) {
	k, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}
	return string(k), nil
}

func signAndWrite(ctx context.Context, cp *fmtlog.Checkpoint, cpNote note.Note, s note.Signer, st *fs.Storage) error {
	cp.Origin = *origin
	cpNote.Text = string(cp.Marshal())
	cpNoteSigned, err := note.Sign(&cpNote, s)
	if err != nil {
		return fmt.Errorf("failed to sign Checkpoint: %w", err)
	}
	if err := st.WriteCheckpoint(ctx, cpNoteSigned); err != nil {
		return fmt.Errorf("failed to store new log checkpoint: %w", err)
	}
	return nil
}

// writeFileIfNotExists writes key files. Ensures files do not already exist to avoid accidental overwriting.
func writeFileIfNotExists(filename string, key string) error {
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("unable to create new key file %q: %w", filename, err)
	}
	_, err = file.WriteString(key)
	if err != nil {
		return fmt.Errorf("unable to write new key file %q: %w", filename, err)
	}
	return file.Close()
}
