// Copyright 2022-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"github.com/veraison/services/handler"
	"github.com/veraison/services/plugin"
	scheme "github.com/veraison/services/scheme/tpm-enacttrust"
)

func main() {
	handler.RegisterEndorsementHandler(&scheme.EndorsementHandler{})
	handler.RegisterEvidenceHandler(&scheme.EvidenceHandler{})
	plugin.Serve()
}
