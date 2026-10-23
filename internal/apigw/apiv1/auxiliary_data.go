package apiv1

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// elementPath is the claims path pointer of an mso_mdoc element: its
// namespace in the MDDL, then the element.
func elementPath(meta *model.CredentialMetadata, element string) ([]string, error) {
	schema := meta.GetMDDL()
	if schema == nil {
		return nil, fmt.Errorf("auxiliary data claims need an MDDL")
	}
	for namespace, claims := range schema.Claims {
		if _, ok := claims[element]; ok {
			return []string{namespace, element}, nil
		}
	}
	return nil, fmt.Errorf("the MDDL declares no element %q", element)
}

func hashCommitment(path []string) openid4vci.AuxiliaryDataEntry {
	return openid4vci.AuxiliaryDataEntry{Type: openid4vci.AuxiliaryDataTypeHashCommitment, Alg: "sha-256", Path: path}
}

// announceAuxiliaryData publishes auxiliary_data_supported for the
// credentials with auxiliary data claims.
func (c *Client) announceAuxiliaryData() error {
	for scope, meta := range c.cfg.Common.CredentialMetadata {
		if meta == nil || meta.AuxiliaryData == nil {
			continue
		}
		supported := &openid4vci.AuxiliaryDataSupported{}
		for _, element := range meta.AuxiliaryData.ToWallet {
			path, err := elementPath(meta, element)
			if err != nil {
				return fmt.Errorf("credential_metadata.%s: %w", scope, err)
			}
			supported.ToWallet = append(supported.ToWallet, hashCommitment(path))
		}
		for _, element := range meta.AuxiliaryData.ToIssuer {
			path, err := elementPath(meta, element)
			if err != nil {
				return fmt.Errorf("credential_metadata.%s: %w", scope, err)
			}
			supported.ToIssuer = append(supported.ToIssuer, hashCommitment(path))
		}
		config := c.issuerMetadata.CredentialConfigurationsSupported[scope]
		config.AuxiliaryDataSupported = supported
		c.issuerMetadata.CredentialConfigurationsSupported[scope] = config
	}
	return nil
}

// walletAuxiliaryData reads the auxiliary_data of the request's first key
// proof. Call it only after the proofs are verified.
func walletAuxiliaryData(req *openid4vci.CredentialRequest) ([]openid4vci.AuxiliaryDataEntry, error) {
	switch {
	case req.Proof != nil && req.Proof.ProofType == "jwt":
		return openid4vci.ProofJWTToken(req.Proof.JWT).ExtractAuxiliaryData()
	case req.Proofs != nil && len(req.Proofs.JWT) > 0:
		return req.Proofs.JWT[0].ExtractAuxiliaryData()
	case req.Proofs != nil && len(req.Proofs.Attestation) > 0:
		return req.Proofs.Attestation[0].ExtractAuxiliaryData()
	default:
		return nil, nil
	}
}

// applyAuxiliaryData writes the auxiliary data claims of scope into the
// document data, and returns the entries for the response: a random
// 16-byte opening for each to_wallet claim, and the wallet's commitment,
// as sent, for each to_issuer claim.
func (c *Client) applyAuxiliaryData(scope string, documentData []byte, req *openid4vci.CredentialRequest) ([]byte, []openid4vci.AuxiliaryDataEntry, error) {
	meta := c.cfg.GetCredentialMetadata(scope)
	if meta == nil || meta.AuxiliaryData == nil {
		return documentData, nil, nil
	}
	if len(meta.AuxiliaryData.ToWallet) > 0 && req.CredentialResponseEncryption == nil {
		return nil, nil, &openid4vci.Error{
			Err:              openid4vci.ErrInvalidEncryptionParameters,
			ErrorDescription: "the opening is only sent in an encrypted response; request credential_response_encryption",
		}
	}

	var doc map[string]any
	if err := json.Unmarshal(documentData, &doc); err != nil {
		return nil, nil, err
	}

	var toWallet []openid4vci.AuxiliaryDataEntry
	for _, element := range meta.AuxiliaryData.ToWallet {
		path, err := elementPath(meta, element)
		if err != nil {
			return nil, nil, err
		}
		opening := make([]byte, 16)
		if _, err := rand.Read(opening); err != nil {
			return nil, nil, err
		}
		commitment := sha256.Sum256(opening)
		doc[element] = base64.StdEncoding.EncodeToString(commitment[:])
		entry := hashCommitment(path)
		entry.Opening = base64.RawURLEncoding.EncodeToString(opening)
		toWallet = append(toWallet, entry)
	}

	fromWallet, err := walletAuxiliaryData(req)
	if err != nil {
		return nil, nil, &openid4vci.Error{Err: openid4vci.ErrInvalidProof, ErrorDescription: err.Error()}
	}
	for _, element := range meta.AuxiliaryData.ToIssuer {
		path, err := elementPath(meta, element)
		if err != nil {
			return nil, nil, err
		}
		for _, entry := range fromWallet {
			if entry.Type != openid4vci.AuxiliaryDataTypeHashCommitment || !slices.Equal(entry.Path, path) {
				continue
			}
			commitment, err := base64.RawURLEncoding.DecodeString(entry.Commitment)
			if err != nil || len(commitment) != sha256.Size {
				return nil, nil, &openid4vci.Error{Err: openid4vci.ErrInvalidProof, ErrorDescription: fmt.Sprintf("%q needs a base64url sha-256 commitment", element)}
			}
			doc[element] = base64.StdEncoding.EncodeToString(commitment)
		}
	}

	out, err := json.Marshal(doc)
	return out, toWallet, err
}
