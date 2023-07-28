// Copyright 2022-2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package keylime

import (
	"fmt"

	"github.com/veraison/corim/comid"
)

type InstanceAttributes struct {
	AgentID string
}

func (o *InstanceAttributes) FromEnvironment(e comid.Environment) error {
	inst := e.Instance

	if inst == nil {
		return fmt.Errorf("expecting instance in environment")
	}

	agentID, err := e.Instance.GetUUID()
	if err != nil {
		return fmt.Errorf("could not extract node-id (UUID) from instance-id")
	}

	o.AgentID = agentID.String()

	return nil
}
