package openid4vci

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The wire members are the extension's: the examples below are taken from
// openid-4-verifiable-credential-issuance-auxiliary-data.md.
func TestAuxiliaryDataWireShape(t *testing.T) {
	psc := AuxiliaryDataEntry{
		Type: AuxiliaryDataTypeHashCommitment, Alg: "sha-256",
		Path: []string{"eu.europa.ec.eudi.nym_auth.1", "psc"}, Commitment: "JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0",
	}

	t.Run("a key proof carries auxiliary_data", func(t *testing.T) {
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"https://credential-issuer.example.com","iat":1792576000,
			"nonce":"LarRGSbmUPYtRYO6BQ4yn8","auxiliary_data":[{"type":"hash_commitment","alg":"sha-256",
			"path":["eu.europa.ec.eudi.nym_auth.1","psc"],"commitment":"JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0"}]}`))
		token := "eyJhbGciOiJFUzI1NiJ9." + payload + ".c2ln"

		fromJWT, err := ProofJWTToken(token).ExtractAuxiliaryData()
		require.NoError(t, err)
		assert.Equal(t, []AuxiliaryDataEntry{psc}, fromJWT)

		fromAttestation, err := ProofAttestation(token).ExtractAuxiliaryData()
		require.NoError(t, err)
		assert.Equal(t, []AuxiliaryDataEntry{psc}, fromAttestation)
	})

	t.Run("a credential configuration announces auxiliary_data_supported", func(t *testing.T) {
		encoded, err := json.Marshal(CredentialConfigurationsSupported{
			Format: "mso_mdoc", Doctype: "eu.europa.ec.eudi.nym_auth.1",
			AuxiliaryDataSupported: &AuxiliaryDataSupported{
				ToWallet: []AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: []string{"eu.europa.ec.eudi.nym_auth.1", "ssc"}}},
				ToIssuer: []AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: []string{"eu.europa.ec.eudi.nym_auth.1", "psc"}}},
			},
		})
		require.NoError(t, err)
		assert.JSONEq(t, `{"format": "mso_mdoc", "doctype": "eu.europa.ec.eudi.nym_auth.1",
			"auxiliary_data_supported": {
				"to_wallet": [{"type": "hash_commitment", "alg": "sha-256", "path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"]}],
				"to_issuer": [{"type": "hash_commitment", "alg": "sha-256", "path": ["eu.europa.ec.eudi.nym_auth.1", "psc"]}]}}`,
			string(encoded))
	})

	t.Run("a response carries auxiliary_data in credential_metadata", func(t *testing.T) {
		published := &CredentialMetadata{Display: []CredentialMetadataDisplay{{Name: "nym_auth"}}}
		response := &CredentialResponse{
			Credentials:        []Credential{{Credential: "ompuYW1lU3BhY2Vz..."}},
			CredentialMetadata: published,
		}
		response.AddAuxiliaryData(AuxiliaryDataEntry{
			Type: AuxiliaryDataTypeHashCommitment, Alg: "sha-256",
			Path: []string{"eu.europa.ec.eudi.nym_auth.1", "ssc"}, Opening: "So-cHS4_SltsfY6fChssPQ",
		})

		encoded, err := json.Marshal(response)
		require.NoError(t, err)
		assert.JSONEq(t, `{"credentials": [{"credential": "ompuYW1lU3BhY2Vz..."}],
			"credential_metadata": {"display": [{"name": "nym_auth"}],
				"auxiliary_data": [{"type": "hash_commitment", "alg": "sha-256",
					"path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"], "opening": "So-cHS4_SltsfY6fChssPQ"}]}}`,
			string(encoded))
		assert.Empty(t, published.AuxiliaryData, "the published issuer metadata must not receive the opening")
	})
}
