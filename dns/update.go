package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

	"cloud.google.com/go/compute/metadata"
)

const (
	// DefaultTTL is the default time-to-live for DNS records in seconds (5 minutes).
	DefaultTTL int64 = 300

	defaultManagedZone = "sebi-wan-kenobi-org"
)

// Options contains configurable settings for updating a Cloud DNS record.
type Options struct {
	IPs           []net.IP
	ProjectID     string
	ManagedZone   string
	TTL           int64
	Service       *dns.Service
	ClientOptions []option.ClientOption
}

// Option is a functional option for configuring UpdateWithOptions.
type Option func(*Options)

// WithIP specifies a target IP address for the DNS record.
func WithIP(ip net.IP) Option {
	return func(o *Options) {
		if ip != nil {
			o.IPs = append(o.IPs, ip)
		}
	}
}

// WithIPs specifies multiple target IP addresses for the DNS record.
func WithIPs(ips ...net.IP) Option {
	return func(o *Options) {
		for _, ip := range ips {
			if ip != nil {
				o.IPs = append(o.IPs, ip)
			}
		}
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

// Update updates Google Cloud DNS A and/or AAAA records for the specified hostname using the Google Cloud DNS API.
//
// Parameters:
//   - ctx: Context for network requests and cancellation (defaults to context.Background() if nil).
//   - projectID: Google Cloud Project ID. If empty, it is detected from environment variables
//     (GOOGLE_CLOUD_PROJECT, GCLOUD_PROJECT, GCP_PROJECT).
//   - managedZone: Cloud DNS Managed Zone name. If empty, it is automatically discovered by matching the hostname
//     against the project's managed zones in Cloud DNS.
//   - hostname: The target domain name to update (e.g. "home.example.com").
//   - ips: One or more IP addresses (IPv4 and/or IPv6) to set.
func Update(ctx context.Context, projectID, managedZone, host string, ips ...net.IP) error {
	var validIPs []net.IP
	for _, ip := range ips {
		if ip != nil {
			validIPs = append(validIPs, ip)
		}
	}
	if len(validIPs) == 0 {
		return fmt.Errorf("no ip provided")
	}

	var ipStrs []string
	for _, ip := range validIPs {
		ipStrs = append(ipStrs, ip.String())
	}
	log.Printf("Updating IP(s) of %q to %q in zone %q for project %q", host, strings.Join(ipStrs, ", "), managedZone, projectID)
	return UpdateWithOptions(ctx, host, validIPs,
		WithProject(projectID),
		WithZone(managedZone),
	)
}

// UpdateWithOptions updates Google Cloud DNS A and/or AAAA records with advanced configurations and functional options.
func UpdateWithOptions(ctx context.Context, host string, ips []net.IP, opts ...Option) error {
	if ctx == nil {
		ctx = context.Background()
	}

	options := &Options{
		TTL: DefaultTTL,
		IPs: ips,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(options)
		}
	}

	host = strings.TrimSpace(host)
	if host == "" {
		return errors.New("hostname cannot be empty")
	}
	canonicalName := canonicalizeHostname(host)

	var validIPs []net.IP
	for _, ip := range options.IPs {
		if ip != nil {
			validIPs = append(validIPs, ip)
		}
	}
	if len(validIPs) == 0 {
		return errors.New("no ip provided")
	}

	// 2. Resolve Project ID
	projectID, err := detectProjectID(ctx, options.ProjectID)
	if err != nil {
		return err
	}
	log.Printf("Resolved project ID: %s", projectID)

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
		return errors.New("managed zone cannot be empty")
	}

	ttl := options.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}

	var aRrdatas []string
	var aaaaRrdatas []string

	for _, ip := range validIPs {
		if ip.To4() == nil {
			log.Printf("IPv6 address detected: %s", ip.String())
			aaaaRrdatas = append(aaaaRrdatas, ip.String())

			addr, err := netip.ParseAddr(ip.String())
			if err == nil && addr.Is4In6() {
				log.Printf("IPv4 mapped IPv6 detected: %s", ip.String())
				aRrdatas = append(aRrdatas, addr.Unmap().String())
			}
		} else {
			log.Printf("IPv4 address detected: %s", ip.String())
			aRrdatas = append(aRrdatas, ip.String())
		}
	}

	var records []*dns.ResourceRecordSet
	if len(aRrdatas) > 0 {
		records = append(records, &dns.ResourceRecordSet{
			Name:    canonicalName,
			Type:    "A",
			Ttl:     ttl,
			Rrdatas: aRrdatas,
		})
	}
	if len(aaaaRrdatas) > 0 {
		records = append(records, &dns.ResourceRecordSet{
			Name:    canonicalName,
			Type:    "AAAA",
			Ttl:     ttl,
			Rrdatas: aaaaRrdatas,
		})
	}

	// 5. Query existing record for this hostname using Cloud DNS API
	listResp, err := dnsSrv.ResourceRecordSets.List(projectID, managedZone).Name(canonicalName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to query DNS record sets for %s in zone %s: %w", canonicalName, managedZone, err)
	}

	var deletions []*dns.ResourceRecordSet
	for _, rr := range listResp.Rrsets {
		if canonicalizeHostname(rr.Name) == canonicalName && (rr.Type == "A" || rr.Type == "AAAA") {
			deletions = append(deletions, rr)
		}
	}

	// If record already exists with identical IP and TTL, no change is necessary
	if len(deletions) == len(records) {
		allMatch := true
		for _, rec := range records {
			matched := false
			for _, existing := range deletions {
				if existing.Type == rec.Type && existing.Ttl == rec.Ttl &&
					canonicalizeHostname(existing.Name) == canonicalizeHostname(rec.Name) &&
					slicesEqual(existing.Rrdatas, rec.Rrdatas) {
					matched = true
					break
				}
			}
			if !matched {
				allMatch = false
				break
			}
		}
		if allMatch {
			log.Printf("DNS records for %s are already up to date, skipping change", canonicalName)
			return nil
		}
	}

	// 6. Build atomic Change for Cloud DNS API
	change := &dns.Change{
		Additions: records,
		Deletions: deletions,
	}

	// 7. Apply change via Google Cloud DNS Changes API
	var ipStrings []string
	for _, ip := range validIPs {
		ipStrings = append(ipStrings, ip.String())
	}
	log.Printf("Applying DNS change for %s (%s) in zone %s: %+v", canonicalName, strings.Join(ipStrings, ", "), managedZone, change)
	_, err = dnsSrv.Changes.Create(projectID, managedZone, change).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("failed to apply DNS change for %s (%s) in zone %s: %w", canonicalName, strings.Join(ipStrings, ", "), managedZone, err)
	}

	return nil
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// UpdateHTTP is the entrypoint handler for Google Cloud Functions (HTTP trigger).
// It only accepts HTTP POST requests with a JSON body or form parameters, verifies authentication
// (if configured via AUTH_TOKEN), extracts the hostname and target IP(s), and invokes Update.
func UpdateHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Only allow HTTP POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed: only POST requests are accepted", http.StatusMethodNotAllowed)
		return
	}

	// 2. Parse JSON body (if provided) and/or Form values
	var payload struct {
		Host        string `json:"host"`
		Hostname    string `json:"hostname"`
		IPv4        string `json:"ipv4"`
		IPv6        string `json:"ipv6"`
		Token       string `json:"token"`
		ManagedZone string `json:"managed_zone"`
		ProjectID   string `json:"project_id"`
	}

	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(strings.ToLower(contentType), "application/json") || (r.Body != nil && r.ContentLength > 0 && !strings.Contains(contentType, "application/x-www-form-urlencoded")) {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 10240))
		if err != nil {
			http.Error(w, fmt.Sprintf("Bad Request: failed to read body: %v", err), http.StatusBadRequest)
			return
		}
		if len(strings.TrimSpace(string(bodyBytes))) > 0 {
			if err := json.Unmarshal(bodyBytes, &payload); err != nil {
				http.Error(w, fmt.Sprintf("Bad Request: invalid JSON body: %v", err), http.StatusBadRequest)
				return
			}
		}
	} else if r.Body != nil {
		_ = r.ParseForm()
	}

	// Also fallback to URL Query / Form values if fields are unset
	if payload.Host == "" {
		payload.Host = r.FormValue("host")
	}
	if payload.Host == "" {
		payload.Host = r.FormValue("hostname")
	}
	if payload.Host == "" && payload.Hostname != "" {
		payload.Host = payload.Hostname
	}
	if payload.IPv4 == "" {
		payload.IPv4 = r.FormValue("ipv4")
	}
	if payload.IPv6 == "" {
		payload.IPv6 = r.FormValue("ipv6")
	}
	if payload.Token == "" {
		payload.Token = r.FormValue("token")
	}
	if payload.ManagedZone == "" {
		payload.ManagedZone = r.FormValue("managed_zone")
	}
	if payload.ProjectID == "" {
		payload.ProjectID = r.FormValue("project_id")
	}

	// 3. Verify Authentication if AUTH_TOKEN is set in the environment
	if expectedToken := strings.TrimSpace(os.Getenv("AUTH_TOKEN")); expectedToken != "" {
		token := strings.TrimSpace(payload.Token)
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
				token = strings.TrimSpace(authHeader[7:])
			}
		}
		if token == "" {
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

	// 4. Resolve Hostname
	host := strings.TrimSpace(payload.Host)
	if host == "" {
		http.Error(w, "Bad Request: missing required 'host' in JSON body or POST params", http.StatusBadRequest)
		return
	}

	// 5. Resolve Target IP address(es)
	var targetIPs []net.IP

	// Check if explicit IPv4 is provided
	if ipv4Str := strings.TrimSpace(payload.IPv4); ipv4Str != "" {
		parsedIPv4 := net.ParseIP(ipv4Str)
		if parsedIPv4 == nil || parsedIPv4.To4() == nil {
			http.Error(w, fmt.Sprintf("Bad Request: invalid IPv4 address %q", ipv4Str), http.StatusBadRequest)
			return
		}
		targetIPs = append(targetIPs, parsedIPv4)
	}

	// Check if explicit IPv6 is provided
	if ipv6Str := strings.TrimSpace(payload.IPv6); ipv6Str != "" {
		parsedIPv6 := net.ParseIP(ipv6Str)
		if parsedIPv6 == nil || parsedIPv6.To4() != nil {
			http.Error(w, fmt.Sprintf("Bad Request: invalid IPv6 address %q", ipv6Str), http.StatusBadRequest)
			return
		}
		targetIPs = append(targetIPs, parsedIPv6)
	}

	// If no IP was specified at all, fallback to extracting caller's IP
	if len(targetIPs) == 0 {
		callerIP := extractCallerIP(r)
		if callerIP == nil {
			http.Error(w, "IP could not be determined", http.StatusInternalServerError)
			return
		}
		targetIPs = append(targetIPs, callerIP)
	}

	// 6. Update DNS record in Google Cloud DNS
	projectID := strings.TrimSpace(payload.ProjectID)
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if projectID == "" {
		projectID = os.Getenv("GCP_PROJECT")
	}
	managedZone := strings.TrimSpace(payload.ManagedZone)
	if managedZone == "" {
		managedZone = os.Getenv("MANAGED_ZONE")
	}
	if managedZone == "" {
		managedZone = defaultManagedZone
	}

	err := Update(ctx, projectID, managedZone, host, targetIPs...)
	if err != nil {
		log.Printf("Failed to update DNS record: %v", err)
		http.Error(w, fmt.Sprintf("Failed to update DNS record: %v", err), http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"status": "OK",
		"host":   host,
	}
	var ipStrs []string
	for _, tip := range targetIPs {
		ipStrs = append(ipStrs, tip.String())
		if tip.To4() != nil {
			resp["ipv4"] = tip.String()
		} else {
			resp["ipv6"] = tip.String()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// extractCallerIP extracts the client's public IP address (IPv4 or IPv6) from HTTP request headers.
func extractCallerIP(r *http.Request) net.IP {
	// 1. Check X-Forwarded-For (standard for Cloud Functions, Cloud Run, and HTTP load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for _, part := range ips {
			clientIP := strings.TrimSpace(part)
			if host, _, err := net.SplitHostPort(clientIP); err == nil {
				clientIP = host
			}
			clientIP = strings.Trim(clientIP, "[]")
			if parsed := net.ParseIP(clientIP); parsed != nil {
				log.Printf("Using X-Forwarded-For IP %s", parsed.String())
				return parsed
			}
		}
	}

	// 2. Check X-Real-IP
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		clientIP := xrip
		if host, _, err := net.SplitHostPort(clientIP); err == nil {
			clientIP = host
		}
		clientIP = strings.Trim(clientIP, "[]")
		if parsed := net.ParseIP(clientIP); parsed != nil {
			log.Printf("Using X-Real-IP IP %s", parsed.String())
			return parsed
		}
	}

	// 3. Fallback to RemoteAddr
	if r.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		host = strings.Trim(host, "[]")
		if parsed := net.ParseIP(host); parsed != nil {
			log.Printf("Using remote addr %q", r.RemoteAddr)
			return parsed
		}
	}
	log.Printf("No IP address found.")
	return nil
}

func detectProjectID(ctx context.Context, projectID string) (string, error) {
	if val := strings.TrimSpace(projectID); val != "" {
		return val, nil
	}
	for _, envVar := range []string{"GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "GCP_PROJECT"} {
		if val := strings.TrimSpace(os.Getenv(envVar)); val != "" {
			return val, nil
		}
	}
	if metadata.OnGCE() {
		if pid, err := metadata.ProjectIDWithContext(ctx); err == nil && strings.TrimSpace(pid) != "" {
			return strings.TrimSpace(pid), nil
		}
	}
	return "", errors.New("Google Cloud Project ID is not specified and could not be detected from environment (GOOGLE_CLOUD_PROJECT, GCLOUD_PROJECT, GCP_PROJECT) or GCP metadata server")
}

func canonicalizeHostname(hostname string) string {
	h := strings.TrimSpace(strings.ToLower(hostname))
	if !strings.HasSuffix(h, ".") {
		h += "."
	}
	return h
}

func init() {
	funcframework.RegisterHTTPFunction("/", UpdateHTTP)
}
