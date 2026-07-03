package models

import (
	"encoding/json"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestSessionAndFlowStateMetadataAutoMigrate(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/session-meta.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	if !db.Migrator().HasColumn(&Session{}, "session_meta") {
		t.Fatalf("sessions.session_meta column missing")
	}
	if !db.Migrator().HasColumn(&FlowState{}, "meta") {
		t.Fatalf("flow_states.meta column missing")
	}
}

func TestSessionAndFlowStateMetadataRoundTrip(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/session-meta-roundtrip.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	sessionMeta := JSON(json.RawMessage(`{"required_team":"team_123","authorized_team_scopes":["team:team_123"]}`))
	session := Session{UserID: 1, InstanceId: "tenant_abc", SessionMeta: sessionMeta}
	if err := db.Create(&session).Error; err != nil {
		t.Fatalf("create session: %v", err)
	}
	var loadedSession Session
	if err := db.First(&loadedSession, session.ID).Error; err != nil {
		t.Fatalf("load session: %v", err)
	}
	if string(loadedSession.SessionMeta) != string(sessionMeta) {
		t.Fatalf("session meta mismatch: %s", string(loadedSession.SessionMeta))
	}

	flowMeta := JSON(json.RawMessage(`{"required_team":"team_123"}`))
	flow := FlowState{
		AuthCode:             "code_1",
		CodeChallengeMethod:  "plain",
		CodeChallenge:        "challenge",
		CodeVerifier:         "verifier",
		ProviderType:         "mock",
		AuthenticationMethod: "oauth",
		InstanceId:           "tenant_abc",
		Meta:                 flowMeta,
	}
	if err := db.Create(&flow).Error; err != nil {
		t.Fatalf("create flow: %v", err)
	}
	var loadedFlow FlowState
	if err := db.First(&loadedFlow, flow.ID).Error; err != nil {
		t.Fatalf("load flow: %v", err)
	}
	if string(loadedFlow.Meta) != string(flowMeta) {
		t.Fatalf("flow meta mismatch: %s", string(loadedFlow.Meta))
	}
}
