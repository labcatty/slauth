package services

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/thecybersailor/slauth/pkg/models"
)

func TestFlowStateMetaRoundTripsThroughAuthService(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_abc")

	meta := models.JSON(json.RawMessage(`{"required_team":"team_123"}`))
	flow := &models.FlowState{
		AuthCode:             "code_flow_meta",
		CodeChallengeMethod:  "plain",
		CodeChallenge:        "challenge",
		CodeVerifier:         "verifier",
		ProviderType:         "mock",
		AuthenticationMethod: "oauth",
		InstanceId:           "tenant_abc",
		Meta:                 meta,
	}
	if err := service.CreateFlowState(context.Background(), flow); err != nil {
		t.Fatalf("create flow state: %v", err)
	}
	loaded, err := service.GetFlowStateByID(context.Background(), flow.ID)
	if err != nil {
		t.Fatalf("get flow state: %v", err)
	}
	if string(loaded.Meta) != string(meta) {
		t.Fatalf("meta mismatch: %s", string(loaded.Meta))
	}
}
