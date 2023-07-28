// Copyright 2021-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package keylime

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	tpm2 "github.com/google/go-tpm/tpm2"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/veraison/ear"

	"github.com/veraison/services/handler"
	"github.com/veraison/services/proto"
	"github.com/veraison/services/scheme/common"
)

type MBParseRequest struct {
	MBMeasurementList string `json:"mb_measurement_list"`
	HashAlg           string `json:"hash_alg"`
}

type MBParseResponse struct {
	BootAggregates  map[string][]string    `json:"boot_aggregates"`
	PCRHashes       map[string]int         `json:"pcr_hashes`
	MeasurementData map[string]interface{} `json:"mb_measurement_data"`
}

type MBValidateRequest struct {
	MBMeasurementData map[string]interface{} `json:"mb_measurement_data"`
	MbRefState        string                 `json:"mb_refstate"`
	PCRsInQuote       []int64                `json:"pcrs_inquote"`
}

type MBValidateResponse struct {
	Failure string `json:"failure"`
}

type EvidenceHandler struct{}

func (s EvidenceHandler) GetName() string {
	return "keylime-evidence-handler"
}

func (s EvidenceHandler) GetAttestationScheme() string {
	return SchemeName
}

func (s EvidenceHandler) GetSupportedMediaTypes() []string {
	return EvidenceMediaTypes
}

func (s EvidenceHandler) SynthKeysFromRefValue(
	tenantID string,
	swComp *proto.Endorsement,
) ([]string, error) {
	return synthKeysFromParts("software component", tenantID, swComp.GetAttributes())
}

func (s EvidenceHandler) SynthKeysFromTrustAnchor(tenantID string, ta *proto.Endorsement) ([]string, error) {
	return synthKeysFromParts("trust anchor", tenantID, ta.GetAttributes())
}

func (s EvidenceHandler) GetTrustAnchorID(token *proto.AttestationToken) (string, error) {
	supported := false
	for _, mt := range EvidenceMediaTypes {
		if token.MediaType == mt {
			supported = true
			break
		}
	}

	if !supported {
		err := handler.BadEvidence(
			"wrong media type: expect %q, but found %q",
			strings.Join(EvidenceMediaTypes, ", "),
			token.MediaType,
		)
		return "", err
	}

	var decoded Token

	if err := decoded.Decode(token.Data); err != nil {
		return "", handler.BadEvidence("Could not decode token: %s", err)
	}

	return keylimeLookupKey(token.TenantId, decoded.AgentID.String()), nil
}

func (s EvidenceHandler) ExtractClaims(
	token *proto.AttestationToken,
	trustAnchor string,
) (*handler.ExtractedClaims, error) {
	supported := false
	for _, mt := range EvidenceMediaTypes {
		if token.MediaType == mt {
			supported = true
			break
		}
	}

	if !supported {
		return nil, fmt.Errorf("wrong media type: expect %q, but found %q",
			strings.Join(EvidenceMediaTypes, ", "),
			token.MediaType,
		)
	}

	var decoded Token

	if err := decoded.Decode(token.Data); err != nil {
		return nil, fmt.Errorf("could not decode token: %w", err)
	}

	if decoded.Quote.AttestationData.Type != tpm2.TagAttestQuote {
		return nil, fmt.Errorf("wrong TPMS_ATTEST type: want %d, got %d",
			tpm2.TagAttestQuote, decoded.Quote.AttestationData.Type)
	}

	var pcrs []interface{} // nolint:prealloc
	for _, pcr := range decoded.Quote.AttestationData.AttestedQuoteInfo.PCRSelection.PCRs {
		pcrs = append(pcrs, int64(pcr))
	}

	// Let Keylime parse the UEFI Measured Boot log

	request := MBParseRequest{
		MBMeasurementList: decoded.MBMeasurementList,
		HashAlg:           "sha256",
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(REST_ENDPOINT+"/mb/parse", "application/json", bytes.NewReader(requestJSON))
	if err != nil {
		return nil, err
	}

	var data []byte
	var response MBParseResponse
	_, err = resp.Body.Read(data)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &response)
	if err != nil {
		return nil, err
	}

	evidence := handler.NewExtractedClaims()
	evidence.ClaimsSet["pcr-selection"] = pcrs
	evidence.ClaimsSet["hash-alg"] = int64(decoded.Quote.AttestationData.AttestedQuoteInfo.PCRSelection.Hash)
	evidence.ClaimsSet["agent-id"] = decoded.AgentID
	evidence.ClaimsSet["pcr-digest"] = []byte(decoded.Quote.AttestationData.AttestedQuoteInfo.PCRDigest)
	evidence.ClaimsSet["mb_measurment_list"] = decoded.MBMeasurementList
	evidence.ClaimsSet["mb_measurment_data"] = response.MeasurementData
	evidence.ClaimsSet["pcr_hashes"] = response.PCRHashes
	evidence.ReferenceID = keylimeLookupKey(token.TenantId, decoded.AgentID.String())
	return evidence, nil
}

func (s EvidenceHandler) ValidateEvidenceIntegrity(
	token *proto.AttestationToken,
	trustAnchor string,
	endorsements []string,
) error {
	var decoded Token
	var taEndorsement TrustAnchorEndorsement

	if err := decoded.Decode(token.Data); err != nil {
		return handler.BadEvidence("could not decode token: %w", err)
	}

	if err := json.Unmarshal([]byte(trustAnchor), &taEndorsement); err != nil {
		return handler.ParseError(err)
	}

	buf, err := base64.StdEncoding.DecodeString(taEndorsement.Attr.Key)
	if err != nil {
		return handler.ParseError(err)
	}

	public, err := tpm2.DecodePublic(buf)
	if err != nil {
		return handler.ParseError(err)
	}

	public_key, err := public.Key()
	if err != nil {
		return handler.ParseError(err)
	}

	if err := decoded.VerifySignature((*crypto.PublicKey)(&public_key)); err != nil {
		return handler.BadEvidence("Signature verification failed: %w", err)
	}

	return nil
}

func (s EvidenceHandler) AppraiseEvidence(
	ec *proto.EvidenceContext,
	endorsementStrings []string,
) (*ear.AttestationResult, error) {
	result := handler.CreateAttestationResult(SchemeName)
	evidence := ec.Evidence.AsMap()
	mbMeasurementDataValue, ok := evidence["mb_measurement_data"]
	if !ok {
		err := handler.BadEvidence(
			"evidence does not contain %q entry",
			"mb_measurement_data",
		)
		return result, err
	}

	mbMeasurementData, ok := mbMeasurementDataValue.(map[string]interface{})
	if !ok {
		err := handler.BadEvidence(
			"wrong type value %q entry; expected string but found %T",
			"mb_measurement_list",
			mbMeasurementData,
		)
		return result, err
	}

	PCRSelectionValue, ok := evidence["pcr-selection"]
	if !ok {
		err := handler.BadEvidence(
			"evidence does not contain %q entry",
			"pcr-selection",
		)
		return result, err
	}

	PCRSelection, ok := PCRSelectionValue.([]int64)
	if !ok {
		err := handler.BadEvidence(
			"wrong type value %q entry; expected string but found %T",
			"pcr-selection",
			PCRSelection,
		)
		return result, err
	}

	var endorsements Endorsements
	if err := endorsements.Populate(endorsementStrings); err != nil {
		return result, err
	}

	request := MBValidateRequest{
		MBMeasurementData: mbMeasurementData,
		MbRefState:        endorsements.MbRefState,
		PCRsInQuote:       PCRSelection,
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return result, err
	}

	resp, err := http.Post(REST_ENDPOINT+"/mb/validate", "application/json", bytes.NewReader(requestJSON))
	if err != nil {
		return result, err
	}

	var data []byte
	_, err = resp.Body.Read(data)
	if err != nil {
		return result, err
	}

	var mbResponse MBValidateResponse
	err = json.Unmarshal(data, &mbResponse)
	if err != nil {
		return result, err
	}

	appraisal := result.Submods[SchemeName]
	appraisal.VeraisonAnnotatedEvidence = &evidence

	if mbResponse.Failure == "" {
		appraisal.TrustVector.Executables = ear.ApprovedBootClaim
		*appraisal.Status = ear.TrustTierAffirming
	}

	return result, nil
}

func synthKeysFromParts(scope, tenantID string, parts *structpb.Struct) ([]string, error) {
	var (
		agentID string
		fields  map[string]*structpb.Value
		err     error
	)

	fields, err = common.GetFieldsFromParts(parts)
	if err != nil {
		return nil, fmt.Errorf("unable to synthesize %s abs-path: %w", scope, err)
	}

	agentID, err = common.GetMandatoryPathSegment("keylime.agent-id", fields)
	if err != nil {
		return nil, fmt.Errorf("unable to synthesize %s abs-path: %w", scope, err)
	}

	return []string{keylimeLookupKey(tenantID, agentID)}, nil
}

func keylimeLookupKey(tenantID, AgentID string) string {
	absPath := []string{AgentID}

	u := url.URL{
		Scheme: SchemeName,
		Host:   tenantID,
		Path:   strings.Join(absPath, "/"),
	}

	return u.String()
}
