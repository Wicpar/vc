package openid4vci

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Credential Auxiliary Data carries data that goes with a Credential at
// issuance and stays outside it
// (openid-4-verifiable-credential-issuance-auxiliary-data.md in
// sirosfoundation/nym_auth_rulebook). The Wallet sends entries in its key
// proofs, the Credential Issuer sends entries in the response-level
// credential_metadata, and the credential configuration announces both.

// AuxiliaryDataTypeHashCommitment is the Auxiliary Data Type the
// extension defines.
const AuxiliaryDataTypeHashCommitment = "hash_commitment"

// AuxiliaryDataEntry is one Auxiliary Data Entry. Type names the
// Auxiliary Data Type; the other members are those of hash_commitment.
type AuxiliaryDataEntry struct {
	// Type is the Auxiliary Data Type.
	Type string `json:"type"`

	// Alg is the hash function of a hash_commitment.
	Alg string `json:"alg,omitempty"`

	// Path is the claims path pointer of the claim that holds the
	// commitment.
	Path []string `json:"path,omitempty"`

	// Opening is the base64url secret, in an entry the Credential Issuer
	// sends. It is a Secret Value.
	Opening string `json:"opening,omitempty"`

	// Commitment is the base64url commitment, in an entry the Wallet
	// sends.
	Commitment string `json:"commitment,omitempty"`

	// Required, in a to_issuer entry, means the Wallet must send it.
	Required bool `json:"required,omitempty"`
}

// AuxiliaryDataSupported is the auxiliary_data_supported parameter of a
// credential configuration.
type AuxiliaryDataSupported struct {
	// ToWallet lists the entries the Credential Issuer sends in each
	// response that carries Credentials.
	ToWallet []AuxiliaryDataEntry `json:"to_wallet,omitempty" yaml:"to_wallet,omitempty"`

	// ToIssuer lists the entries the Credential Issuer accepts in key
	// proofs.
	ToIssuer []AuxiliaryDataEntry `json:"to_issuer,omitempty" yaml:"to_issuer,omitempty"`
}

// AddAuxiliaryData adds entries to the response-level
// credential_metadata.
//
// The response may share its credential_metadata with the published
// issuer metadata, so the object is copied before it is written.
func (r *CredentialResponse) AddAuxiliaryData(entries ...AuxiliaryDataEntry) {
	metadata := CredentialMetadata{}
	if r.CredentialMetadata != nil {
		metadata = *r.CredentialMetadata
	}
	metadata.AuxiliaryData = append(slices.Clone(metadata.AuxiliaryData), entries...)
	r.CredentialMetadata = &metadata
}

// jwtPayload decodes the payload of a compact JWT into v, without
// verifying its signature.
func jwtPayload(token string, v any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	return json.Unmarshal(payload, v)
}
