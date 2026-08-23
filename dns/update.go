package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
)

// DefaultTTL is the default time-to-live for DNS records in seconds (5 minutes).
const DefaultTTL int64 = 300

// Options contains configurable settings for updating a Cloud DNS record.
type Options struct {
	IP            string
	ProjectID     string
	ManagedZone   string
	TTL           int64
	Service       *dns.Service
	ClientOptions []option.ClientOption
}

// Option is a functional option for configuring UpdateWithOptions.
type Option func(*Options)

// WithIP specifies the target IPv4 address for the DNS record.
func WithIP(ip string) Option {
	return func(o *Options) {
		o.IP = ip
	}
}

// WithProject sets the Google Cloud Project ID.
func WithProject(projectID string) Option {
	return func(o *Options) {
		o.ProjectID = projectID
	}
}

// WithZone sets the Google Cloud DNS managed zone name.
func WithZone(zone string) Option {
	return func(o *Options) {
		o.ManagedZone = zone
	}
}

// WithTTL sets the TTL (in seconds) for the DNS record.
func WithTTL(ttl int64) Option {
	return func(o *Options) {
		o.TTL = ttl
	}
}

// WithService provides a pre-configured Google Cloud DNS service client.
func WithService(srv *dns.Service) Option {
	return func(o *Options) {
		o.Service = srv
	}
}

// WithClientOptions configures options for the Google Cloud DNS client.
func WithClientOptions(opts ...option.ClientOption) Option {
	return func(o *Options) {
		o.ClientOptions = append(o.ClientOptions, opts...)
	}
}

// Update updates a Google Cloud DNS A record for the specified hostname using the Google Cloud DNS API.
//
// Parameters:
//   - ctx: Context for network requests and cancellation (defaults to context.Background() if nil).
//   - projectID: Google Cloud Project ID. If empty, it is detected from environment variables
//     (GOOGLE_CLOUD_PROJECT, GCLOUD_PROJECT, GCP_PROJECT).
//   - managedZone: Cloud DNS Managed Zone name. If empty, it is automatically discovered by matching the hostname
//     against the project's managed zones in Cloud DNS.
//   - hostname: The target domain name to update (e.g. "home.example.com").
//   - ip: Optional IPv4 address. If omitted or passed as an empty string, the caller's public IP address
//     is automatically detected.
func Update(ctx context.Context, projectID, managedZone, hostname string, ip ...string) error {
	var targetIP string
	if len(ip) > 0 {
		targetIP = ip[0]
	}
	return UpdateWithOptions(ctx, hostname,
		WithProject(projectID),
		WithZone(managedZone),
		WithIP(targetIP),
	)
}

// UpdateWithOptions updates a Google Cloud DNS A record with advanced configurations and functional options.
func UpdateWithOptions(ctx context.Context, hostname string, opts ...Option) error {
	if ctx == nil {
		ctx = context.Background()
	}

	options := &Options{
		TTL: DefaultTTL,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}

	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return errors.New("hostname cannot be empty")
	}
	canonicalName := canonicalizeHostname(hostname)

	// 1. Resolve Target IP address
	targetIP := strings.TrimSpace(options.IP)
	if targetIP == "" {
		callerIP, err := GetCallerIP(ctx)
		if err != nil {
			return fmt.Errorf("failed to detect caller IP: %w", err)
		}
		targetIP = callerIP
	}

	// Validate IPv4 format
	parsedIP := net.ParseIP(targetIP)
	if parsedIP == nil || parsedIP.To4() == nil {
		return fmt.Errorf("invalid IPv4 address %q for DNS A record", targetIP)
	}
	targetIP = parsedIP.To4().String()

	// 2. Resolve Project ID
	projectID, err := detectProjectID(options.ProjectID)
	if err != nil {
		return err
	}

	// 3. Initialize Google Cloud DNS Service Client if not provided
	dnsSrv := options.Service
	if dnsSrv == nil {
		var clientOpts []option.ClientOption
		if len(options.ClientOptions) > 0 {
			clientOpts = options.ClientOptions
		}
		var svcErr error
		dnsSrv, svcErr = dns.NewService(ctx, clientOpts...)
		if svcErr != nil {
			return fmt.Errorf("failed to create Google Cloud DNS service client: %w", svcErr)
		}
	}

	// 4. Resolve Managed Zone if not provided
	managedZone := strings.TrimSpace(options.ManagedZone)
	if managedZone == "" {
		discoveredZone, err := FindManagedZone(ctx, dnsSrv, projectID, canonicalName)
		if err != nil {
			return err
		}
		managedZone = discoveredZone
	}

	ttl := options.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	newRecord := &dns.ResourceRecordSet{
		Name:    canonicalName,
		Type:    "A",
		Ttl:     ttl,
		Rrdatas: []string{targetIP},
	}

	// 5. Query existing A record for this hostname using Cloud DNS API
	listResp, err := dnsSrv.ResourceRecordSets.List(projectID, managedZone).Name(canonicalName).Type("A").Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to query DNS record sets for %s in zone %s: %w", canonicalName, managedZone, err)
	}

	var existingRecord *dns.ResourceRecordSet
	for _, rr := range listResp.Rrsets {
		if canonicalizeHostname(rr.Name) == canonicalName && rr.Type == "A" {
			existingRecord = rr
			break
		}
	}

	// If record already exists with identical IP and TTL, no change is necessary
	if existingRecord != nil {
		if existingRecord.Ttl == ttl && len(existingRecord.Rrdatas) == 1 && existingRecord.Rrdatas[0] == targetIP {
			return nil
		}
	}

	// 6. Build atomic Change for Cloud DNS API
	change := &dns.Change{
		Additions: []*dns.ResourceRecordSet{newRecord},
	}
	if existingRecord != nil {
		change.Deletions = []*dns.ResourceRecordSet{existingRecord}
	}

	// 7. Apply change via Google Cloud DNS Changes API
	_, err = dnsSrv.Changes.Create(projectID, managedZone, change).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to apply DNS change for %s (%s) in zone %s: %w", canonicalName, targetIP, managedZone, err)
	}

	return nil
}

// UpdateHTTP is the entrypoint handler for Google Cloud Functions (HTTP trigger).
// It handles HTTP requests, verifies authentication (if configured via AUTH_TOKEN),
// parses the hostname and IP parameters from query parameters or JSON body,
// automatically extracts the caller's IP from the request headers if omitted,
// and invokes the Google Cloud DNS Update function.
func UpdateHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Verify Authentication if AUTH_TOKEN is set in the environment
	if expectedToken := strings.TrimSpace(os.Getenv("AUTH_TOKEN")); expectedToken != "" {
		token := strings.TrimSpace(r.URL.Query().Get("token"))
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				token = strings.TrimSpace(authHeader[7:])
			}
		}
		if token == "" {
			// Support HTTP Basic Authentication (common with DDNS clients like Fritz!Box / ddclient)
			_, pass, ok := r.BasicAuth()
			if ok && pass != "" {
				token = pass
			}
		}

		if token != expectedToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// 2. Parse Hostname and IP from Query parameters, Form values, or JSON body
	hostname := strings.TrimSpace(r.URL.Query().Get("hostname"))
	if hostname == "" {
		hostname = strings.TrimSpace(r.URL.Query().Get("host"))
	}
	if hostname == "" {
		hostname = strings.TrimSpace(r.URL.Query().Get("domain"))
	}

	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		ip = strings.TrimSpace(r.URL.Query().Get("myip"))
	}
	if ip == "" {
		ip = strings.TrimSpace(r.URL.Query().Get("ipv4"))
	}

	// If not in query params, inspect form or JSON payload
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "application/json") {
			var body struct {
				Hostname string `json:"hostname"`
				Host     string `json:"host"`
				Domain   string `json:"domain"`
				IP       string `json:"ip"`
				MyIP     string `json:"myip"`
			}
			bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 10240))
			if err == nil && len(bodyBytes) > 0 {
				if err := json.Unmarshal(bodyBytes, &body); err == nil {
					if hostname == "" {
						if body.Hostname != "" {
							hostname = body.Hostname
						} else if body.Host != "" {
							hostname = body.Host
						} else {
							hostname = body.Domain
						}
					}
					if ip == "" {
						if body.IP != "" {
							ip = body.IP
						} else {
							ip = body.MyIP
						}
					}
				}
			}
		} else {
			if hostname == "" {
				hostname = strings.TrimSpace(r.FormValue("hostname"))
			}
			if ip == "" {
				ip = strings.TrimSpace(r.FormValue("ip"))
				if ip == "" {
					ip = strings.TrimSpace(r.FormValue("myip"))
				}
			}
		}
	}

	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		http.Error(w, "Missing required 'hostname' parameter", http.StatusBadRequest)
		return
	}

	// 3. If IP address is not specified by the caller, extract it from the HTTP request headers
	if ip == "" {
		ip = extractCallerIP(r)
	}

	// 4. Update DNS record in Google Cloud DNS
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		projectID = os.Getenv("GCP_PROJECT")
	}
	managedZone := os.Getenv("MANAGED_ZONE")

	err := Update(ctx, projectID, managedZone, hostname, ip)
	if err != nil {
		if strings.Contains(err.Error(), "invalid IPv4 address") || strings.Contains(err.Error(), "hostname cannot be empty") {
			http.Error(w, fmt.Sprintf("Bad Request: %v", err), http.StatusBadRequest)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to update DNS record: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK: Updated %s to %s\n", hostname, ip)
}

// extractCallerIP extracts the client's public IPv4 address from HTTP request headers.
func extractCallerIP(r *http.Request) string {
	// 1. Check X-Forwarded-For (standard for Cloud Functions, Cloud Run, and HTTP load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for _, part := range ips {
			clientIP := strings.TrimSpace(part)
			if parsed := net.ParseIP(clientIP); parsed != nil && parsed.To4() != nil {
				return parsed.To4().String()
			}
		}
	}

	// 2. Check X-Real-IP
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		if parsed := net.ParseIP(xrip); parsed != nil && parsed.To4() != nil {
			return parsed.To4().String()
		}
	}

	// 3. Fallback to RemoteAddr
	if r.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if parsed := net.ParseIP(host); parsed != nil && parsed.To4() != nil {
			return parsed.To4().String()
		}
	}

	return ""
}

// GetCallerIP detects the current public IPv4 address of the caller using Google DNS.
func GetCallerIP(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// Method 1: Query Google's authoritative DNS nameservers for TXT o-o.myaddr.l.google.com
	googleNameservers := []string{
		"ns1.google.com:53",
		"ns2.google.com:53",
		"ns3.google.com:53",
		"ns4.google.com:53",
		"216.239.32.10:53",
		"216.239.34.10:53",
	}

	for _, ns := range googleNameservers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(dialCtx, "udp", ns)
			},
		}

		txtRecords, err := resolver.LookupTXT(ctx, "o-o.myaddr.l.google.com")
		if err != nil || len(txtRecords) == 0 {
			continue
		}

		for _, txt := range txtRecords {
			txt = strings.Trim(txt, `" `)
			parsed := net.ParseIP(txt)
			if parsed != nil && parsed.To4() != nil {
				return parsed.To4().String(), nil
			}
		}
	}

	// Method 2: Google Public DNS over HTTPS (DoH) API fallback (dns.google)
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://dns.google/resolve?name=o-o.myaddr.l.google.com&type=TXT", nil)
	if err == nil {
		req.Header.Set("Accept", "application/dns-json")
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var result struct {
					Answer []struct {
						Data string `json:"data"`
					} `json:"Answer"`
				}
				if json.NewDecoder(resp.Body).Decode(&result) == nil {
					for _, ans := range result.Answer {
						clean := strings.Trim(ans.Data, `" `)
						parsed := net.ParseIP(clean)
						if parsed != nil && parsed.To4() != nil {
							return parsed.To4().String(), nil
						}
					}
				}
			}
		}
	}

	return "", errors.New("failed to detect caller public IP address via Google DNS")
}

// FindManagedZone discovers the appropriate managed zone in a GCP project that hosts the given hostname
// using the Google Cloud DNS ManagedZones API.
func FindManagedZone(ctx context.Context, srv *dns.Service, projectID, hostname string) (string, error) {
	canonical := canonicalizeHostname(hostname)
	req := srv.ManagedZones.List(projectID)
	var matchedZone string
	var longestMatchLen int

	err := req.Pages(ctx, func(resp *dns.ManagedZonesListResponse) error {
		for _, zone := range resp.ManagedZones {
			zoneDNS := canonicalizeHostname(zone.DnsName)
			if strings.HasSuffix(canonical, zoneDNS) {
				if len(zoneDNS) > longestMatchLen {
					longestMatchLen = len(zoneDNS)
					matchedZone = zone.Name
				}
			}
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to list managed zones in project %q: %w", projectID, err)
	}

	if matchedZone == "" {
		return "", fmt.Errorf("no managed zone found in project %q matching hostname %q", projectID, hostname)
	}
	return matchedZone, nil
}

func detectProjectID(projectID string) (string, error) {
	if val := strings.TrimSpace(projectID); val != "" {
		return val, nil
	}
	for _, envVar := range []string{"GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "GCP_PROJECT"} {
		if val := strings.TrimSpace(os.Getenv(envVar)); val != "" {
			return val, nil
		}
	}
	return "", errors.New("Google Cloud Project ID is not specified and could not be detected from environment (GOOGLE_CLOUD_PROJECT, GCLOUD_PROJECT, GCP_PROJECT)")
}

func canonicalizeHostname(hostname string) string {
	h := strings.TrimSpace(strings.ToLower(hostname))
	if !strings.HasSuffix(h, ".") {
		h += "."
	}
	return h
}
