// Copyright 2021-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package keylime

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/uuid"
)

type Quote struct {
	Raw             []byte
	AttestationData *tpm2.AttestationData
	Signature       *tpm2.Signature
	PCRs            []byte //TODO parse this structure
}

// Token is the container for the decoded Keylime token
type Token struct {
	AgentID                 uuid.UUID `json:"uuid"`
	Quote                   Quote     `json:"quote"`
	HashAlg                 string    `json:"hash_alg"`
	EncAlg                  string    `json:"enc_alg"`
	SignAlg                 string    `json:"sign_alg"`
	PubKey                  string    `json:"pub_key"`
	BootTime                uint32    `json:"boottime"`
	ImaMeasurementList      string    `json:"ima_measurement_list"`
	ImaMeasurementListEntry uint32    `json:"ima_measurement_list_entry"`
	MBMeasurementList       string    `json:"mb_measurement_list"`
}

func (quote *Quote) UnmarshalJSON(b []byte) error {
	var rawQuote string
	var err error
	var rawSignature []byte
	if err = json.Unmarshal(b, &rawQuote); err != nil {
		return err
	}

	if rawQuote[0] != 'r' {
		return errors.New("Not a quote")
	}

	tokens := strings.Split(rawQuote[1:], ":")

	if len(tokens) != 3 {
		return errors.New("Not a valid quote")
	}

	quote.Raw, err = base64.StdEncoding.DecodeString(tokens[0])
	if err != nil {
		return errors.New("Failed to decode TPMS_ATTEST")
	}

	quote.AttestationData, err = tpm2.DecodeAttestationData(quote.Raw)
	if err != nil {
		return err
	}

	rawSignature, err = base64.StdEncoding.DecodeString(tokens[1])
	if err != nil {
		return errors.New("Failed to decode Signature")
	}

	quote.Signature, err = tpm2.DecodeSignature(bytes.NewBuffer(rawSignature))
	if err != nil {
		return err
	}

	var rawPCRs []byte
	rawPCRs, err = base64.StdEncoding.DecodeString(tokens[2])
	if err != nil {
		s := fmt.Sprintf("FAILED PCR: %s", tokens[2])
		return errors.New(s)
	}

	quote.PCRs = rawPCRs

	return nil
}

func (t *Token) Decode(data []byte) error {
	if err := json.Unmarshal(data, t); err != nil {
		return err
	}
	return nil
}

func (t Token) VerifySignature(key *crypto.PublicKey) error {

	return nil
}
