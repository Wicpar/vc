package apiv1

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nym_auth as config.yaml configures it: the announcement matches the
// rulebook, the opening opens the issued ssc, the wallet's psc is written
// as sent, and the opening never goes out unencrypted.
func TestNymAuthAuxiliaryData(t *testing.T) {
	raw, err := os.ReadFile("../../../metadata/nym_auth.mdoc.json")
	require.NoError(t, err)
	schema, err := mdoc.LoadMDDLSchema(raw)
	require.NoError(t, err)
	client := &Client{
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"nym_auth": {Format: "mso_mdoc", MDDL: schema, AuxiliaryData: &model.AuxiliaryDataClaims{ToWallet: []string{"ssc"}, ToIssuer: []string{"psc"}}},
		}}},
		issuerMetadata: &openid4vci.CredentialIssuerMetadataParameters{
			CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{"nym_auth": {}},
		},
	}

	require.NoError(t, client.announceAuxiliaryData())
	announced, err := json.Marshal(client.issuerMetadata.CredentialConfigurationsSupported["nym_auth"].AuxiliaryDataSupported)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"to_wallet": [{"type": "hash_commitment", "alg": "sha-256", "path": ["eu.europa.ec.eudi.nym_auth.1", "ssc"]}],
		"to_issuer": [{"type": "hash_commitment", "alg": "sha-256", "path": ["eu.europa.ec.eudi.nym_auth.1", "psc"]}]}`,
		string(announced))

	psc := sha256.Sum256([]byte("the wallet's private seed"))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"auxiliary_data":[{"type":"hash_commitment","alg":"sha-256",
		"path":["eu.europa.ec.eudi.nym_auth.1","psc"],"commitment":"` + base64.RawURLEncoding.EncodeToString(psc[:]) + `"}]}`))
	request := &openid4vci.CredentialRequest{
		CredentialResponseEncryption: &openid4vci.CredentialResponseEncryption{},
		Proofs:                       &openid4vci.Proofs{JWT: []openid4vci.ProofJWTToken{openid4vci.ProofJWTToken("e30." + payload + ".c2ln")}},
	}

	out, entries, err := client.applyAuxiliaryData("nym_auth", []byte(`{"birth_date":"2011-06-15"}`), request)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	opening, err := base64.RawURLEncoding.DecodeString(entries[0].Opening)
	require.NoError(t, err)
	assert.Len(t, opening, 16)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	ssc := sha256.Sum256(opening)
	assert.Equal(t, base64.StdEncoding.EncodeToString(ssc[:]), doc["ssc"])
	assert.Equal(t, base64.StdEncoding.EncodeToString(psc[:]), doc["psc"])

	request.CredentialResponseEncryption = nil
	_, _, err = client.applyAuxiliaryData("nym_auth", []byte(`{}`), request)
	var vciErr *openid4vci.Error
	require.ErrorAs(t, err, &vciErr)
	assert.Equal(t, openid4vci.ErrInvalidEncryptionParameters, vciErr.Err)
}
