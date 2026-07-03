# Workbench Session Meta Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add persistent session metadata and team-scope JWT emission so workbench authorization can survive refresh-token renewal.

**Architecture:** Store flow metadata on `FlowState` and persistent authorization metadata on `Session`. Session creation accepts explicit `SessionMeta`, JWT generation derives OAuth-style `scope` from that metadata, and refresh reuses the persisted metadata so `scope=team:<team_id>` survives token rotation.

**Tech Stack:** Go, GORM, SQLite tests, `github.com/golang-jwt/jwt/v5`, existing `models.JSON`.

---

### Task 1: Add Failing Model Tests For Session And Flow Metadata

**Files:**
- Modify: `pkg/models/session.go`
- Modify: `pkg/models/flow_state.go`
- Test: `pkg/models/session_meta_test.go`

**Step 1: Write the failing test**

Create `pkg/models/session_meta_test.go`:

```go
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
```

**Step 2: Run test to verify it fails**

Run:

```bash
go test ./pkg/models -run 'TestSessionAndFlowStateMetadata' -count=1
```

Expected: FAIL because `Session.SessionMeta` and `FlowState.Meta` do not exist.

**Step 3: Write minimal implementation**

Modify `pkg/models/session.go`:

```go
	SessionMeta models.JSON `json:"session_meta,omitempty" gorm:"column:session_meta"`
```

Use the local package type, so the actual line should be:

```go
	SessionMeta JSON `json:"session_meta,omitempty" gorm:"column:session_meta"`
```

Modify `pkg/models/flow_state.go`:

```go
	Meta JSON `json:"meta,omitempty" gorm:"column:meta"`
```

**Step 4: Run test to verify it passes**

Run:

```bash
go test ./pkg/models -run 'TestSessionAndFlowStateMetadata' -count=1
```

Expected: PASS.

**Step 5: Commit**

```bash
git add pkg/models/session.go pkg/models/flow_state.go pkg/models/session_meta_test.go
git commit -m "feat: add session metadata models"
```

### Task 2: Add Failing Service Tests For Team Scope Token Emission

**Files:**
- Modify: `pkg/services/auth_service.go`
- Modify: `pkg/services/auth_service_impl.go`
- Modify: `pkg/services/jwt_service.go`
- Test: `pkg/services/auth_service_session_meta_test.go`

**Step 1: Write the failing test**

Create `pkg/services/auth_service_session_meta_test.go`:

```go
package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/thecybersailor/slauth/pkg/models"
	"github.com/thecybersailor/slauth/pkg/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestCreateAndRefreshSessionPreserveTeamScopeFromSessionMeta(t *testing.T) {
	db := newSessionMetaTokenTestDB(t)
	service := NewAuthServiceImpl(db, newSessionMetaTokenTestSecretsProvider(t), "tenant_abc")
	phone := "+8618616977031"
	user, err := service.GetUserService().CreateUserWithSource(context.Background(), &UserCreateOptions{
		Phone: &phone,
	}, UserCreatedSourceAdmin, nil, nil)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	session, accessToken, _, _, err := service.CreateSessionWithOptions(
		context.Background(),
		user,
		types.AALLevel1,
		[]string{"sms"},
		"test",
		"127.0.0.1",
		SessionOptions{
			Tag: SessionTagWeb,
			SessionMeta: map[string]any{
				"required_team":          "team_123",
				"authorized_team_scopes": []string{"team:team_123"},
			},
		},
	)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	assertAccessTokenScope(t, accessToken, "team:team_123")

	var stored models.Session
	if err := db.First(&stored, session.ID).Error; err != nil {
		t.Fatalf("load stored session: %v", err)
	}
	if len(stored.SessionMeta) == 0 {
		t.Fatalf("expected stored session meta")
	}

	_, refreshedAccessToken, _, _, err := service.RefreshSession(
		context.Background(),
		user,
		session.ID,
		types.AALLevel1,
		[]string{"refresh_token"},
		"test",
		"127.0.0.1",
	)
	if err != nil {
		t.Fatalf("refresh session: %v", err)
	}
	assertAccessTokenScope(t, refreshedAccessToken, "team:team_123")
}

func assertAccessTokenScope(t *testing.T, token string, expected string) {
	t.Helper()
	var parser jwt.Parser
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", parsed.Claims)
	}
	if claims["scope"] != expected {
		t.Fatalf("expected scope %q, got %#v", expected, claims["scope"])
	}
}

func newSessionMetaTokenTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/slauth-session-meta-token.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	return db
}

func newSessionMetaTokenTestSecretsProvider(t *testing.T) *StaticSecretsProvider {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return NewStaticSecretsProvider(&types.InstanceSecrets{
		PrimaryKeyId: "session-meta-test-key",
		AppSecret:    "session-meta-token-test-secret",
		Keys: map[string]*types.SigningKey{
			"session-meta-test-key": {
				Kid:        "session-meta-test-key",
				Algorithm:  types.SignAlgES256,
				PrivateKey: string(privatePEM),
				PublicKey:  string(publicPEM),
			},
		},
	})
}
```

**Step 2: Run test to verify it fails**

Run:

```bash
go test ./pkg/services -run TestCreateAndRefreshSessionPreserveTeamScopeFromSessionMeta -count=1
```

Expected: FAIL because `SessionOptions.SessionMeta` and JWT `scope` are not implemented.

**Step 3: Write minimal implementation**

Modify `pkg/services/auth_service.go`:

```go
type SessionOptions struct {
	Tag         string
	SessionMeta map[string]any
}
```

Modify `pkg/services/auth_service_impl.go`:

- Add helper functions:

```go
func sessionMetaJSON(meta map[string]any) (models.JSON, error) {
	if len(meta) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	return models.JSON(raw), nil
}

func scopeFromSessionMeta(raw models.JSON) string {
	if len(raw) == 0 {
		return ""
	}
	var meta struct {
		AuthorizedTeamScopes []string `json:"authorized_team_scopes"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return ""
	}
	return strings.Join(meta.AuthorizedTeamScopes, " ")
}
```

- In `CreateSessionWithOptions`, marshal `options.SessionMeta`, store it on `session.SessionMeta`, and pass `scopeFromSessionMeta(session.SessionMeta)` to JWT generation.
- In `RefreshSession`, pass `scopeFromSessionMeta(session.SessionMeta)` to JWT generation.

Modify `pkg/services/jwt_service.go`:

- Add `Scope string `json:"scope,omitempty"` to `JWTClaims`.
- Add a trailing `scope string` argument to `GenerateAccessToken` and `GenerateAccessTokenWithExpiry`.
- Set `Scope: scope` in both claim constructors.
- Update all call sites to pass `""` unless they are session creation/refresh paths using session metadata.

**Step 4: Run test to verify it passes**

Run:

```bash
go test ./pkg/services -run TestCreateAndRefreshSessionPreserveTeamScopeFromSessionMeta -count=1
```

Expected: PASS.

**Step 5: Commit**

```bash
git add pkg/services/auth_service.go pkg/services/auth_service_impl.go pkg/services/jwt_service.go pkg/services/auth_service_session_meta_test.go
git commit -m "feat: emit session metadata scopes"
```

### Task 3: Add FlowState Metadata Service Test

**Files:**
- Test: `pkg/services/auth_service_flow_meta_test.go`

**Step 1: Write the failing test**

Create `pkg/services/auth_service_flow_meta_test.go`:

```go
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
```

**Step 2: Run test to verify it fails or passes for the right reason**

Run:

```bash
go test ./pkg/services -run TestFlowStateMetaRoundTripsThroughAuthService -count=1
```

Expected: PASS after Task 1 model implementation; if it fails, fix only the metadata persistence path.

**Step 3: Commit**

```bash
git add pkg/services/auth_service_flow_meta_test.go
git commit -m "test: cover flow state metadata"
```

### Task 4: Run Focused And Package Verification

**Files:**
- No source edits expected.

**Step 1: Run focused model tests**

Run:

```bash
go test ./pkg/models -run 'TestSessionAndFlowStateMetadata' -count=1
```

Expected: PASS.

**Step 2: Run focused service tests**

Run:

```bash
go test ./pkg/services -run 'Test(CreateAndRefreshSessionPreserveTeamScopeFromSessionMeta|FlowStateMetaRoundTripsThroughAuthService)' -count=1
```

Expected: PASS.

**Step 3: Run broader package tests**

Run:

```bash
go test ./pkg/models ./pkg/services -count=1
```

Expected: PASS.

**Step 4: Commit verification notes if no source changed**

No commit is required if no files changed.

### Task 5: Tag The Slauth Version For BotWorks Consumption

**Files:**
- No source edits expected.

**Step 1: Inspect latest tags**

Run:

```bash
git tag --sort=-version:refname | head -20
```

Expected: shows the current latest version tag.

**Step 2: Choose next patch tag**

Use the next patch version after the latest semantic version tag.

**Step 3: Create annotated tag**

Run:

```bash
git tag -a <next-version> -m "Release <next-version>"
```

Expected: tag created locally.

**Step 4: Push commits and tag**

Run:

```bash
git push
git push origin <next-version>
```

Expected: commits and tag are pushed.

**Step 5: Record handoff**

Record the pushed tag in the final response so BotWorks Plan 1.5 can upgrade to it.

