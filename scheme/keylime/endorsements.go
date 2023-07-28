// Copyright 2021-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package keylime

import (
	"encoding/json"
	"fmt"
)

type TaAttr struct {
	AgentID string `json:"keylime.agent-id"`
	Key     string `json:"keylime.ak-pub"`
}

type TrustAnchorEndorsement struct {
	Scheme  string `json:"scheme"`
	Type    string `json:"type"`
	SubType string `json:"sub_type"`
	Attr    TaAttr `json:"attributes"`
}

type RefValAttr struct {
	AgentID    string `json:"keylime.agent-id"`
	MBRefstate string `json:"keylime.mb_refstate"`
}

type RefValEndorsement struct {
	Scheme  string     `json:"scheme"`
	Type    string     `json:"type"`
	SubType string     `json:"sub_type"`
	Attr    RefValAttr `json:"attributes"`
}

type Endorsements struct {
	MbRefState string
}

func (e *Endorsements) Populate(strings []string) error {
	l := len(strings)

	if l != 1 {
		return fmt.Errorf("incorrect endorsements number: want 1, got %d", l)
	}

	var refval RefValEndorsement

	if err := json.Unmarshal([]byte(strings[0]), &refval); err != nil {
		return fmt.Errorf("could not decode reference value: %w", err)
	}

	e.MbRefState = refval.Attr.MBRefstate

	return nil
}
