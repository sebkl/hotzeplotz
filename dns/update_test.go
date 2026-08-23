package dns

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCanonicalizeHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com."},
		{"example.com.", "example.com."},
		{"sub.example.com", "sub.example.com."},
		{"SUB.EXAMPLE.COM", "sub.example.com."},
		{"  my.domain.org  ", "my.domain.org."},
	}

	for _, tt := range tests {
		got := canonicalizeHostname(tt.input)
		if got != tt.expected {
			t.Errorf("canonicalizeHostname(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestDetectProjectID(t *testing.T) {
	// 1. Explicit project ID should take precedence
	proj, err := detectProjectID("explicit-project")
	if err != nil || proj != "explicit-project" {
		t.Fatalf("expected 'explicit-project', got %q (err: %v)", proj, err)
	}

	// 2. Env variable detection
	os.Setenv("GOOGLE_CLOUD_PROJECT", "env-project")
	defer os.Unsetenv("GOOGLE_CLOUD_PROJECT")

	proj, err = detectProjectID("")
	if err != nil || proj != "env-project" {
		t.Fatalf("expected 'env-project', got %q (err: %v)", proj, err)
	}

	// 3. Missing project ID
	os.Unsetenv("GOOGLE_CLOUD_PROJECT")
	os.Unsetenv("GCLOUD_PROJECT")
	os.Unsetenv("GCP_PROJECT")

	_, err = detectProjectID("")
	if err == nil {
		t.Fatal("expected error when no project ID is configured, got nil")
	}
}

func TestUpdate_Validation(t *testing.T) {
	ctx := context.Background()

	// Empty hostname should fail
	err := Update(ctx, "proj", "zone", "")
	if err == nil {
		t.Fatal("expected error for empty hostname, got nil")
	}

	// Invalid IPv4 address format should fail
	err = Update(ctx, "proj", "zone", "host.example.com", "999.999.999.999")
	if err == nil {
		t.Fatal("expected error for invalid IP address, got nil")
	}
}

func TestExtractCallerIP(t *testing.T) {
	// 1. Test X-Forwarded-For header
	req1 := httptest.NewRequest(http.MethodGet, "/update", nil)
	req1.Header.Set("X-Forwarded-For", "198.51.100.25, 10.0.0.1")
	if ip := extractCallerIP(req1); ip != "198.51.100.25" {
		t.Errorf("expected X-Forwarded-For IP '198.51.100.25', got %q", ip)
	}

	// 2. Test X-Real-IP header
	req2 := httptest.NewRequest(http.MethodGet, "/update", nil)
	req2.Header.Set("X-Real-IP", "203.0.113.50")
	if ip := extractCallerIP(req2); ip != "203.0.113.50" {
		t.Errorf("expected X-Real-IP '203.0.113.50', got %q", ip)
	}

	// 3. Test RemoteAddr fallback
	req3 := httptest.NewRequest(http.MethodGet, "/update", nil)
	req3.RemoteAddr = "192.0.2.1:12345"
	if ip := extractCallerIP(req3); ip != "192.0.2.1" {
		t.Errorf("expected RemoteAddr IP '192.0.2.1', got %q", ip)
	}
}

func TestUpdateHTTP_Authentication(t *testing.T) {
	os.Setenv("AUTH_TOKEN", "secret-key-123")
	defer os.Unsetenv("AUTH_TOKEN")

	// 1. Unauthorized request (no token)
	req := httptest.NewRequest(http.MethodGet, "/update?hostname=home.example.com", nil)
	rec := httptest.NewRecorder()
	UpdateHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	// 2. Unauthorized request (wrong token)
	reqWrong := httptest.NewRequest(http.MethodGet, "/update?hostname=home.example.com&token=wrong-key", nil)
	recWrong := httptest.NewRecorder()
	UpdateHTTP(recWrong, reqWrong)
	if recWrong.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, recWrong.Code)
	}

	// 3. Authorized via query param
	reqQuery := httptest.NewRequest(http.MethodGet, "/update?token=secret-key-123", nil)
	recQuery := httptest.NewRecorder()
	UpdateHTTP(recQuery, reqQuery)
	// Should pass auth and fail on missing hostname (400) instead of 401
	if recQuery.Code != http.StatusBadRequest {
		t.Errorf("expected status %d (auth passed, missing hostname), got %d", http.StatusBadRequest, recQuery.Code)
	}

	// 4. Authorized via Bearer header
	reqBearer := httptest.NewRequest(http.MethodGet, "/update", nil)
	reqBearer.Header.Set("Authorization", "Bearer secret-key-123")
	recBearer := httptest.NewRecorder()
	UpdateHTTP(recBearer, reqBearer)
	if recBearer.Code != http.StatusBadRequest {
		t.Errorf("expected status %d (auth passed, missing hostname), got %d", http.StatusBadRequest, recBearer.Code)
	}

	// 5. Authorized via Basic Auth
	reqBasic := httptest.NewRequest(http.MethodGet, "/update", nil)
	reqBasic.SetBasicAuth("user", "secret-key-123")
	recBasic := httptest.NewRecorder()
	UpdateHTTP(recBasic, reqBasic)
	if recBasic.Code != http.StatusBadRequest {
		t.Errorf("expected status %d (auth passed, missing hostname), got %d", http.StatusBadRequest, recBasic.Code)
	}
}

func TestUpdateHTTP_MissingHostname(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	rec := httptest.NewRecorder()
	UpdateHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestUpdateHTTP_JSONBodyParsing(t *testing.T) {
	body := []byte(`{"hostname": "myhost.example.com", "ip": "999.999.999.999"}`)
	req := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	UpdateHTTP(rec, req)
	// Should parse JSON, find invalid IP, and return 400 Bad Request
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}
