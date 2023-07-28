// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package keylime

const SchemeName = "KEYLIME"

const REST_ENDPOINT = "http://192.168.122.241:8080"

var (
	EndorsementMediaTypes = []string{
		"application/corim-unsigned+cbor; profile=http://keylime.dev/veraison/1.0.0",
	}

	EvidenceMediaTypes = []string{
		"application/vnd.keylime.evidence",
	}
)
