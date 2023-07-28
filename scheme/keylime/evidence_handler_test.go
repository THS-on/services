// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package keylime

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/veraison/services/proto"
)

func Test_GetTrustAnchorID_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence/keylime.json")
	require.NoError(t, err)

	token := proto.AttestationToken{
		TenantId:  "1",
		MediaType: "application/vnd.keylime.evidence",
		Data:      tokenBytes,
	}

	expectedTaID := "KEYLIME://1/d432fbb3-d2f1-4a97-9ef7-75bd81c00000"

	handler := &EvidenceHandler{}

	taID, err := handler.GetTrustAnchorID(&token)
	require.NoError(t, err)
	assert.Equal(t, expectedTaID, taID)
}
