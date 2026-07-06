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
	assertAccessTokenSessionMeta(t, accessToken, "team_123")

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
	assertAccessTokenSessionMeta(t, refreshedAccessToken, "team_123")
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

func assertAccessTokenSessionMeta(t *testing.T, token string, expectedTeam string) {
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
	meta, ok := claims["session_meta"].(map[string]any)
	if !ok {
		t.Fatalf("expected session_meta claim, got %#v", claims["session_meta"])
	}
	if meta["required_team"] != expectedTeam {
		t.Fatalf("expected session_meta.required_team %q, got %#v", expectedTeam, meta["required_team"])
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
