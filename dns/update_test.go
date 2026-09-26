package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
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
	ctx := context.Background()

	// 1. Explicit project ID should take precedence
	proj, err := detectProjectID(ctx, "explicit-project")
	if err != nil || proj != "explicit-project" {
		t.Fatalf("expected 'explicit-project', got %q (err: %v)", proj, err)
	}

	// 2. Env variable detection
	os.Setenv("GOOGLE_CLOUD_PROJECT", "env-project")
	defer os.Unsetenv("GOOGLE_CLOUD_PROJECT")

	proj, err = detectProjectID(ctx, "")
	if err != nil || proj != "env-project" {
		t.Fatalf("expected 'env-project', got %q (err: %v)", proj, err)
	}

	// 3. Missing project ID
	os.Unsetenv("GOOGLE_CLOUD_PROJECT")
	os.Unsetenv("GCLOUD_PROJECT")
	os.Unsetenv("GCP_PROJECT")

	_, err = detectProjectID(ctx, "")
	if err == nil {
		t.Fatal("expected error when no project ID is configured, got nil")
	}
}

func TestUpdate_Validation(t *testing.T) {
	ctx := context.Background()

	// Empty host should fail
	err := Update(ctx, "proj", "zone", "", net.ParseIP("192.0.2.1"))
	if err == nil {
		t.Fatal("expected error for empty hostname, got nil")
	}

	// Nil IP address should fail
	err = Update(ctx, "proj", "zone", "host.example.com", nil)
	if err == nil {
		t.Fatal("expected error for nil IP address, got nil")
	}
}

func TestExtractCallerIP(t *testing.T) {
	// 1. Test X-Forwarded-For header with IPv4
	req1 := httptest.NewRequest(http.MethodPost, "/update", nil)
	req1.Header.Set("X-Forwarded-For", "198.51.100.25, 10.0.0.1")
	if ip := extractCallerIP(req1); ip == nil || ip.String() != "198.51.100.25" {
		t.Errorf("expected X-Forwarded-For IP '198.51.100.25', got %v", ip)
	}

	// 1b. Test X-Forwarded-For header with IPv6
	req1b := httptest.NewRequest(http.MethodPost, "/update", nil)
	req1b.Header.Set("X-Forwarded-For", "2001:db8:85a3::8a2e:370:7334, 10.0.0.1")
	if ip := extractCallerIP(req1b); ip == nil || ip.String() != "2001:db8:85a3::8a2e:370:7334" {
		t.Errorf("expected X-Forwarded-For IPv6 '2001:db8:85a3::8a2e:370:7334', got %v", ip)
	}

	// 1c. Test X-Forwarded-For header with bracketed IPv6 and port
	req1c := httptest.NewRequest(http.MethodPost, "/update", nil)
	req1c.Header.Set("X-Forwarded-For", "[2001:db8::1]:8080, 10.0.0.1")
	if ip := extractCallerIP(req1c); ip == nil || ip.String() != "2001:db8::1" {
		t.Errorf("expected X-Forwarded-For IPv6 '2001:db8::1', got %v", ip)
	}

	// 1d. Test X-Forwarded-For header with IPv4-mapped IPv6 address
	req1d := httptest.NewRequest(http.MethodPost, "/update", nil)
	req1d.Header.Set("X-Forwarded-For", "::ffff:198.51.100.25, 10.0.0.1")
	if ip := extractCallerIP(req1d); ip == nil || ip.String() != "198.51.100.25" {
		t.Errorf("expected X-Forwarded-For IPv4-in-IPv6 '198.51.100.25', got %v", ip)
	}

	// 2. Test X-Real-IP header with IPv4
	req2 := httptest.NewRequest(http.MethodPost, "/update", nil)
	req2.Header.Set("X-Real-IP", "203.0.113.50")
	if ip := extractCallerIP(req2); ip == nil || ip.String() != "203.0.113.50" {
		t.Errorf("expected X-Real-IP '203.0.113.50', got %v", ip)
	}

	// 2b. Test X-Real-IP header with IPv6
	req2b := httptest.NewRequest(http.MethodPost, "/update", nil)
	req2b.Header.Set("X-Real-IP", "2001:db8::2")
	if ip := extractCallerIP(req2b); ip == nil || ip.String() != "2001:db8::2" {
		t.Errorf("expected X-Real-IP IPv6 '2001:db8::2', got %v", ip)
	}

	// 2c. Test X-Real-IP header with bracketed IPv6
	req2c := httptest.NewRequest(http.MethodPost, "/update", nil)
	req2c.Header.Set("X-Real-IP", "[2001:db8::2]")
	if ip := extractCallerIP(req2c); ip == nil || ip.String() != "2001:db8::2" {
		t.Errorf("expected X-Real-IP IPv6 '2001:db8::2', got %v", ip)
	}

	// 3. Test RemoteAddr fallback with IPv4
	req3 := httptest.NewRequest(http.MethodPost, "/update", nil)
	req3.RemoteAddr = "192.0.2.1:12345"
	if ip := extractCallerIP(req3); ip == nil || ip.String() != "192.0.2.1" {
		t.Errorf("expected RemoteAddr IP '192.0.2.1', got %v", ip)
	}

	// 3b. Test RemoteAddr fallback with IPv6 and port
	req3b := httptest.NewRequest(http.MethodPost, "/update", nil)
	req3b.RemoteAddr = "[2001:db8::3]:12345"
	if ip := extractCallerIP(req3b); ip == nil || ip.String() != "2001:db8::3" {
		t.Errorf("expected RemoteAddr IPv6 '2001:db8::3', got %v", ip)
	}

	// 3c. Test RemoteAddr fallback with IPv6 without port
	req3c := httptest.NewRequest(http.MethodPost, "/update", nil)
	req3c.RemoteAddr = "2001:db8::3"
	if ip := extractCallerIP(req3c); ip == nil || ip.String() != "2001:db8::3" {
		t.Errorf("expected RemoteAddr IPv6 '2001:db8::3', got %v", ip)
	}

	// 4. Test missing / empty IP sources
	req4 := httptest.NewRequest(http.MethodPost, "/update", nil)
	req4.RemoteAddr = ""
	if ip := extractCallerIP(req4); ip != nil {
		t.Errorf("expected nil for empty IP sources, got %v", ip)
	}
}

func TestUpdateHTTP_MethodNotAllowed(t *testing.T) {
	// GET request should be rejected
	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	rec := httptest.NewRecorder()
	UpdateHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d for GET request, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestUpdateHTTP_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/update", strings.NewReader("not-a-valid-json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	UpdateHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d for invalid JSON, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestUpdateHTTP_Authentication(t *testing.T) {
	os.Setenv("AUTH_TOKEN", "secret-key-123")
	defer os.Unsetenv("AUTH_TOKEN")

	// 1. Unauthorized request (no token)
	body := []byte(`{"host": "home.example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	UpdateHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	// 2. Unauthorized request (wrong token)
	bodyWrong := []byte(`{"host": "home.example.com", "token": "wrong-key"}`)
	reqWrong := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(bodyWrong))
	recWrong := httptest.NewRecorder()
	UpdateHTTP(recWrong, reqWrong)
	if recWrong.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, recWrong.Code)
	}

	// 3. Authorized via JSON body token
	bodyJSONToken := []byte(`{"token": "secret-key-123"}`)
	reqJSONToken := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(bodyJSONToken))
	recJSONToken := httptest.NewRecorder()
	UpdateHTTP(recJSONToken, reqJSONToken)
	// Should pass auth and fail on missing host (400) instead of 401
	if recJSONToken.Code != http.StatusBadRequest {
		t.Errorf("expected status %d (auth passed, missing host), got %d", http.StatusBadRequest, recJSONToken.Code)
	}

	// 4. Authorized via Bearer header
	bodyBearer := []byte(`{}`)
	reqBearer := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(bodyBearer))
	reqBearer.Header.Set("Authorization", "Bearer secret-key-123")
	recBearer := httptest.NewRecorder()
	UpdateHTTP(recBearer, reqBearer)
	if recBearer.Code != http.StatusBadRequest {
		t.Errorf("expected status %d (auth passed, missing host), got %d", http.StatusBadRequest, recBearer.Code)
	}

	// 5. Authorized via Basic Auth
	bodyBasic := []byte(`{}`)
	reqBasic := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(bodyBasic))
	reqBasic.SetBasicAuth("user", "secret-key-123")
	recBasic := httptest.NewRecorder()
	UpdateHTTP(recBasic, reqBasic)
	if recBasic.Code != http.StatusBadRequest {
		t.Errorf("expected status %d (auth passed, missing host), got %d", http.StatusBadRequest, recBasic.Code)
	}
}

func TestUpdateHTTP_MissingHost(t *testing.T) {
	body := []byte(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(body))
	req.Header.Set("X-Forwarded-For", "198.51.100.25")
	rec := httptest.NewRecorder()
	UpdateHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestUpdateHTTP_InvalidPayloadIP(t *testing.T) {
	body := []byte(`{"host": "home.example.com", "ipv4": "999.999.999.999"}`)
	req := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	UpdateHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d for invalid IP in payload, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestUpdateHTTP_MissingCallerIP(t *testing.T) {
	body := []byte(`{"host": "home.example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(body))
	req.RemoteAddr = ""
	rec := httptest.NewRecorder()
	UpdateHTTP(rec, req)
	// Without IP in payload or any IP headers / RemoteAddr, caller IP cannot be determined -> 500 Internal Server Error
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
}

func TestUpdateHTTP_DualStack(t *testing.T) {
	// 1. Valid JSON body with both ipv4 and ipv6
	body := []byte(`{"host": "home.example.com", "ipv4": "198.51.100.1", "ipv6": "2001:db8::1"}`)
	req := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	UpdateHTTP(rec, req)
	// Without GCP credentials it will fail at Update stage with 500, but validate it passed JSON parsing and IP validation
	if rec.Code == http.StatusBadRequest {
		t.Errorf("expected request to pass validation, got 400: %s", rec.Body.String())
	}

	// 2. Invalid IPv4 in ipv4 field (passing an IPv6)
	bodyInvalidV4 := []byte(`{"host": "home.example.com", "ipv4": "2001:db8::1"}`)
	reqInvalidV4 := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(bodyInvalidV4))
	recInvalidV4 := httptest.NewRecorder()
	UpdateHTTP(recInvalidV4, reqInvalidV4)
	if recInvalidV4.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for IPv6 in ipv4 field, got %d", recInvalidV4.Code)
	}

	// 3. Invalid IPv6 in ipv6 field (passing an IPv4)
	bodyInvalidV6 := []byte(`{"host": "home.example.com", "ipv6": "198.51.100.1"}`)
	reqInvalidV6 := httptest.NewRequest(http.MethodPost, "/update", bytes.NewReader(bodyInvalidV6))
	recInvalidV6 := httptest.NewRecorder()
	UpdateHTTP(recInvalidV6, reqInvalidV6)
	if recInvalidV6.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for IPv4 in ipv6 field, got %d", recInvalidV6.Code)
	}

	// 4. Form urlencoded POST with both ipv4 and ipv6
	formBody := strings.NewReader("host=home.example.com&ipv4=198.51.100.1&ipv6=2001:db8::1")
	reqForm := httptest.NewRequest(http.MethodPost, "/update", formBody)
	reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recForm := httptest.NewRecorder()
	UpdateHTTP(recForm, reqForm)
	if recForm.Code == http.StatusBadRequest {
		t.Errorf("expected form request to pass validation, got 400: %s", recForm.Body.String())
	}
}

func TestUpdateWithOptions_MockDNS(t *testing.T) {
	ctx := context.Background()

	t.Run("Identical IPv4 record exists - no change made", func(t *testing.T) {
		changesMade := false
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/rrsets") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dns.ResourceRecordSetsListResponse{
					Rrsets: []*dns.ResourceRecordSet{
						{Name: "home.example.com.", Type: "A", Ttl: 300, Rrdatas: []string{"198.51.100.1"}},
					},
				})
				return
			}
			if strings.Contains(r.URL.Path, "/changes") {
				changesMade = true
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dns.Change{Id: "1", Status: "done"})
				return
			}
		}))
		defer server.Close()

		srv, err := dns.NewService(ctx, option.WithEndpoint(server.URL), option.WithoutAuthentication())
		if err != nil {
			t.Fatalf("failed to create dns client: %v", err)
		}

		err = UpdateWithOptions(ctx, "home.example.com", []net.IP{net.ParseIP("198.51.100.1")},
			WithProject("test-project"),
			WithZone("test-zone"),
			WithService(srv),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if changesMade {
			t.Errorf("expected no changes to be created when record is identical")
		}
	})

	t.Run("Update IPv4 to IPv6 - replaces old A record with AAAA", func(t *testing.T) {
		var createdChange *dns.Change
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/rrsets") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dns.ResourceRecordSetsListResponse{
					Rrsets: []*dns.ResourceRecordSet{
						{Name: "home.example.com.", Type: "A", Ttl: 300, Rrdatas: []string{"198.51.100.1"}},
					},
				})
				return
			}
			if strings.Contains(r.URL.Path, "/changes") {
				var ch dns.Change
				json.NewDecoder(r.Body).Decode(&ch)
				createdChange = &ch
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dns.Change{Id: "1", Status: "done"})
				return
			}
		}))
		defer server.Close()

		srv, err := dns.NewService(ctx, option.WithEndpoint(server.URL), option.WithoutAuthentication())
		if err != nil {
			t.Fatalf("failed to create dns client: %v", err)
		}

		err = UpdateWithOptions(ctx, "home.example.com", []net.IP{net.ParseIP("2001:db8::1")},
			WithProject("test-project"),
			WithZone("test-zone"),
			WithService(srv),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if createdChange == nil {
			t.Fatalf("expected Change to be created")
		}
		if len(createdChange.Deletions) != 1 || createdChange.Deletions[0].Type != "A" {
			t.Errorf("expected deletion of old A record, got %+v", createdChange.Deletions)
		}
		if len(createdChange.Additions) != 1 || createdChange.Additions[0].Type != "AAAA" || createdChange.Additions[0].Rrdatas[0] != "2001:db8::1" {
			t.Errorf("expected addition of new AAAA record, got %+v", createdChange.Additions)
		}
	})

	t.Run("Update IPv4 to new IPv4 - replaces old A with new A", func(t *testing.T) {
		var createdChange *dns.Change
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/rrsets") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dns.ResourceRecordSetsListResponse{
					Rrsets: []*dns.ResourceRecordSet{
						{Name: "home.example.com.", Type: "A", Ttl: 300, Rrdatas: []string{"198.51.100.1"}},
					},
				})
				return
			}
			if strings.Contains(r.URL.Path, "/changes") {
				var ch dns.Change
				json.NewDecoder(r.Body).Decode(&ch)
				createdChange = &ch
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dns.Change{Id: "1", Status: "done"})
				return
			}
		}))
		defer server.Close()

		srv, err := dns.NewService(ctx, option.WithEndpoint(server.URL), option.WithoutAuthentication())
		if err != nil {
			t.Fatalf("failed to create dns client: %v", err)
		}

		err = UpdateWithOptions(ctx, "home.example.com", []net.IP{net.ParseIP("198.51.100.2")},
			WithProject("test-project"),
			WithZone("test-zone"),
			WithService(srv),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if createdChange == nil {
			t.Fatalf("expected Change to be created")
		}
		if len(createdChange.Deletions) != 1 || createdChange.Deletions[0].Rrdatas[0] != "198.51.100.1" {
			t.Errorf("expected deletion of old IP, got %+v", createdChange.Deletions)
		}
		if len(createdChange.Additions) != 1 || createdChange.Additions[0].Rrdatas[0] != "198.51.100.2" {
			t.Errorf("expected addition of new IP, got %+v", createdChange.Additions)
		}
	})

	t.Run("Update when both A and AAAA exist - deletes both and sets new record", func(t *testing.T) {
		var createdChange *dns.Change
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/rrsets") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dns.ResourceRecordSetsListResponse{
					Rrsets: []*dns.ResourceRecordSet{
						{Name: "home.example.com.", Type: "A", Ttl: 300, Rrdatas: []string{"198.51.100.1"}},
						{Name: "home.example.com.", Type: "AAAA", Ttl: 300, Rrdatas: []string{"2001:db8::1"}},
					},
				})
				return
			}
			if strings.Contains(r.URL.Path, "/changes") {
				var ch dns.Change
				json.NewDecoder(r.Body).Decode(&ch)
				createdChange = &ch
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dns.Change{Id: "1", Status: "done"})
				return
			}
		}))
		defer server.Close()

		srv, err := dns.NewService(ctx, option.WithEndpoint(server.URL), option.WithoutAuthentication())
		if err != nil {
			t.Fatalf("failed to create dns client: %v", err)
		}

		err = UpdateWithOptions(ctx, "home.example.com", []net.IP{net.ParseIP("2001:db8::2")},
			WithProject("test-project"),
			WithZone("test-zone"),
			WithService(srv),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if createdChange == nil {
			t.Fatalf("expected Change to be created")
		}
		if len(createdChange.Deletions) != 2 {
			t.Errorf("expected 2 deletions (A and AAAA), got %+v", createdChange.Deletions)
		}
		if len(createdChange.Additions) != 1 || createdChange.Additions[0].Type != "AAAA" || createdChange.Additions[0].Rrdatas[0] != "2001:db8::2" {
			t.Errorf("expected 1 AAAA addition with new IPv6, got %+v", createdChange.Additions)
		}
	})

	t.Run("Update with both IPv4 and IPv6 - creates both A and AAAA records", func(t *testing.T) {
		var createdChange *dns.Change
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/rrsets") {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dns.ResourceRecordSetsListResponse{
					Rrsets: []*dns.ResourceRecordSet{
						{Name: "home.example.com.", Type: "A", Ttl: 300, Rrdatas: []string{"198.51.100.1"}},
					},
				})
				return
			}
			if strings.Contains(r.URL.Path, "/changes") {
				var ch dns.Change
				json.NewDecoder(r.Body).Decode(&ch)
				createdChange = &ch
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(dns.Change{Id: "1", Status: "done"})
				return
			}
		}))
		defer server.Close()

		srv, err := dns.NewService(ctx, option.WithEndpoint(server.URL), option.WithoutAuthentication())
		if err != nil {
			t.Fatalf("failed to create dns client: %v", err)
		}

		err = UpdateWithOptions(ctx, "home.example.com", []net.IP{
			net.ParseIP("198.51.100.2"),
			net.ParseIP("2001:db8::1"),
		},
			WithProject("test-project"),
			WithZone("test-zone"),
			WithService(srv),
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if createdChange == nil {
			t.Fatalf("expected Change to be created")
		}
		if len(createdChange.Additions) != 2 {
			t.Fatalf("expected 2 additions (A and AAAA), got %d: %+v", len(createdChange.Additions), createdChange.Additions)
		}
		var hasA, hasAAAA bool
		for _, rec := range createdChange.Additions {
			if rec.Type == "A" && len(rec.Rrdatas) == 1 && rec.Rrdatas[0] == "198.51.100.2" {
				hasA = true
			}
			if rec.Type == "AAAA" && len(rec.Rrdatas) == 1 && rec.Rrdatas[0] == "2001:db8::1" {
				hasAAAA = true
			}
		}
		if !hasA || !hasAAAA {
			t.Errorf("expected both A and AAAA additions, got %+v", createdChange.Additions)
		}
	})
}
