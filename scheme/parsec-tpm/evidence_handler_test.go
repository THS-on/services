// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package parsec_tpm

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/veraison/services/proto"
)

func Test_GetTrustAnchorID_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence/evidence.cbor")
	require.NoError(t, err)

	token := proto.AttestationToken{
		TenantId: "1",
		Data:     tokenBytes,
	}

	expectedTaID := "PARSEC_TPM://1/AYiFVFnuuemzSkbrSMs58vaqadoEUioybRI9XFAfziEM"

	handler := &EvidenceHandler{}

	taID, err := handler.GetTrustAnchorID(&token)
	require.NoError(t, err)
	assert.Equal(t, expectedTaID, taID)
}

func Test_ExtractClaims_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence/evidence.cbor")
	require.NoError(t, err)

	taEndValBytes, err := os.ReadFile("test/evidence/ta_endorsements.json")
	require.NoError(t, err)

	handler := &EvidenceHandler{}

	token := proto.AttestationToken{
		TenantId: "0",
		Data:     tokenBytes,
	}

	ex, err := handler.ExtractClaims(&token, string(taEndValBytes))
	require.NoError(t, err)
	claims := ex.ClaimsSet
	assert.Equal(t, claims["kat"].(map[string]interface{})["kid"].(string), claims["pat"].(map[string]interface{})["kid"].(string))
}

func Test_ExtractClaims_nok_bad_evidence(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence/bad_evidence.cbor")
	require.NoError(t, err)

	taEndValBytes, err := os.ReadFile("test/evidence/ta_endorsements.json")
	require.NoError(t, err)
	expectedErr := "CBOR decoding of Parsec TPM attestation failed cbor: invalid additional information 28 for type byte string"
	h := &EvidenceHandler{}

	token := proto.AttestationToken{
		TenantId: "0",
		Data:     tokenBytes,
	}

	_, err = h.ExtractClaims(&token, string(taEndValBytes))
	err1 := errors.Unwrap(err)
	require.NotNil(t, err1)
	assert.EqualError(t, err1, expectedErr)
}

func Test_ExtractClaims_nok_bad_endorsement(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence/evidence.cbor")
	require.NoError(t, err)

	taEndValBytes, err := os.ReadFile("test/evidence/bad_ta_endorsements.json")
	require.NoError(t, err)
	expectedErr := "could not decode endorsement: json: cannot unmarshal number into Go struct field TaAttr.attributes.parsec-tpm.class-id of type string"
	h := &EvidenceHandler{}

	token := proto.AttestationToken{
		TenantId: "0",
		Data:     tokenBytes,
	}

	_, err = h.ExtractClaims(&token, string(taEndValBytes))
	assert.EqualError(t, err, expectedErr)
}

func Test_ValidateEvidenceIntegrity_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence/evidence.cbor")
	require.NoError(t, err)

	taEndValBytes, err := os.ReadFile("test/evidence/ta_endorsements.json")
	require.NoError(t, err)
	h := &EvidenceHandler{}
	token := proto.AttestationToken{
		TenantId: "1",
		Data:     tokenBytes,
	}
	err = h.ValidateEvidenceIntegrity(&token, string(taEndValBytes), nil)
	require.NoError(t, err)
}

func Test_ValidateEvidenceIntegrity_nok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence/evidence1.cbor")
	require.NoError(t, err)

	taEndValBytes, err := os.ReadFile("test/evidence/ta_endorsements.json")
	require.NoError(t, err)
	expectedErr := "failed to verify signature on key attestation token: failed to verify signature: Verification failed"
	h := &EvidenceHandler{}

	token := proto.AttestationToken{
		TenantId: "1",
		Data:     tokenBytes,
	}

	err = h.ValidateEvidenceIntegrity(&token, string(taEndValBytes), nil)
	err1 := errors.Unwrap(err)
	require.NotNil(t, err1)
	assert.EqualError(t, err1, expectedErr)
}

func Test_ValidateEvidenceIntegrity_BadKey(t *testing.T) {
	tvs := []struct {
		desc        string
		input       string
		expectedErr string
	}{
		{
			desc:        "invalid public key",
			input:       "test/evidence/bad_key_endorsements.json",
			expectedErr: `could not get public key from trust anchor: unable to parse public key: asn1: structure error: tags don't match (16 vs {class:0 tag:2 length:1 isCompound:false}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} AlgorithmIdentifier @2`,
		},
		{
			desc:        "bad pem key header",
			input:       "test/evidence/bad_key_header_endorsements.json",
			expectedErr: `could not get public key from trust anchor: could not extract trust anchor PEM block`,
		},
		{
			desc:        "incorrect key type",
			input:       "test/evidence/bad_key_private_key.json",
			expectedErr: "could not get public key from trust anchor: unsupported key type: \"PRIVATE KEY\"",
		},
	}

	for _, tv := range tvs {
		tokenBytes, err := os.ReadFile("test/evidence/evidence.cbor")
		require.NoError(t, err)

		taEndValBytes, err := os.ReadFile(tv.input)
		require.NoError(t, err)
		h := &EvidenceHandler{}

		token := proto.AttestationToken{
			TenantId: "1",
			Data:     tokenBytes,
		}

		err = h.ValidateEvidenceIntegrity(&token, string(taEndValBytes), nil)
		assert.EqualError(t, err, tv.expectedErr)
	}
}
func Test_AppraiseEvidence_nok(t *testing.T) {
	tvs := []struct {
		desc        string
		input       string
		expectedErr string
	}{
		{
			desc:        "no matching pcr values in endorsements",
			input:       "test/evidence/unmatch_pcr_endorsements.json",
			expectedErr: `match PCR failed: unmatched pcr value: 1 at index: 0`,
		},
		{
			desc:        "umatched PCR Digest Information",
			input:       "test/evidence/unmatch_pcr_digest_endorsements.json",
			expectedErr: `match failed for PCR Digest: PCR Digest and Endorsement Digest match failed`,
		},
	}

	for _, tv := range tvs {
		var endorsemementsArray []string
		extractedBytes, err := os.ReadFile("test/evidence/extracted.json")
		require.NoError(t, err)

		var ec proto.EvidenceContext
		err = json.Unmarshal(extractedBytes, &ec)
		require.NoError(t, err)
		endorsementsBytes, err := os.ReadFile(tv.input)
		require.NoError(t, err)
		err = json.Unmarshal(endorsementsBytes, &endorsemementsArray)
		require.NoError(t, err)

		handler := &EvidenceHandler{}

		_, err = handler.AppraiseEvidence(&ec, endorsemementsArray)
		assert.EqualError(t, err, tv.expectedErr)
	}
}

func Test_AppraiseEvidence_ok(t *testing.T) {
	var endorsemementsArray []string
	extractedBytes, err := os.ReadFile("test/evidence/matched_extracted.json")
	require.NoError(t, err)

	var ec proto.EvidenceContext
	err = json.Unmarshal(extractedBytes, &ec)
	require.NoError(t, err)
	endorsementsBytes, err := os.ReadFile("test/evidence/match_pcr_digest_endorsements.json")
	require.NoError(t, err)
	err = json.Unmarshal(endorsementsBytes, &endorsemementsArray)
	require.NoError(t, err)

	handler := &EvidenceHandler{}

	_, err = handler.AppraiseEvidence(&ec, endorsemementsArray)
	require.NoError(t, err)
}

func Test_SynthKeysFromTrustAnchor_ok(t *testing.T) {
	endorsementsBytes, err := os.ReadFile("test/evidence/ta_endorsements.json")
	require.NoError(t, err)

	var endors proto.Endorsement
	err = json.Unmarshal(endorsementsBytes, &endors)
	require.NoError(t, err)
	expectedKey := "PARSEC_TPM://1/AagIEsUMYDNxd1p5UuAACkxJGfJf9rcUZ/oyRFHDcAxn"

	scheme := &EvidenceHandler{}
	key_list, err := scheme.SynthKeysFromTrustAnchor("1", &endors)
	require.NoError(t, err)
	assert.Equal(t, expectedKey, key_list[0])

}

func Test_SynthKeysFromRefValue_ok(t *testing.T) {
	endorsementsBytes, err := os.ReadFile("test/evidence/refval-endorsements.json")
	require.NoError(t, err)

	var endors proto.Endorsement
	err = json.Unmarshal(endorsementsBytes, &endors)
	require.NoError(t, err)
	expectedKey := "PARSEC_TPM://1/cd1f0e55-26f9-460d-b9d8-f7fde171787c"

	scheme := &EvidenceHandler{}
	key_list, err := scheme.SynthKeysFromRefValue("1", &endors)
	require.NoError(t, err)
	assert.Equal(t, expectedKey, key_list[0])
}

func Test_GetName_ok(t *testing.T) {
	scheme := &EvidenceHandler{}
	expectedName := "parsec-tpm-evidence-handler"
	name := scheme.GetName()
	assert.Equal(t, name, expectedName)
}

func Test_GetAttestationScheme_ok(t *testing.T) {
	scheme := &EvidenceHandler{}
	expectedScheme := "PARSEC_TPM"
	name := scheme.GetAttestationScheme()
	assert.Equal(t, name, expectedScheme)
}

func Test_GetSupportedMediaTypes_ok(t *testing.T) {
	expectedMt := "application/vnd.parallaxsecond.key-attestation.tpm"
	scheme := &EvidenceHandler{}
	mtList := scheme.GetSupportedMediaTypes()
	assert.Len(t, mtList, 1)
	assert.Equal(t, mtList[0], expectedMt)
}
