package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

type TokenClaims struct {
	Hostnames []string  `json:"hostnames"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}

func main() {
	keyName := flag.String("key", "", "Google Cloud KMS symmetric key resource name (projects/.../locations/.../keyRings/.../cryptoKeys/...)")
	hosts := flag.String("hosts", "", "Comma-separated list of allowed hostnames")
	expiresIn := flag.Duration("expires", 365*24*time.Hour, "Duration until token expires (default 1 year)")

	flag.Parse()

	if *keyName == "" || *hosts == "" {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	hostList := strings.Split(*hosts, ",")
	for i, h := range hostList {
		hostList[i] = strings.TrimSpace(h)
	}

	claims := TokenClaims{
		Hostnames: hostList,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(*expiresIn),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		log.Fatalf("Failed to marshal claims: %v", err)
	}

	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}
	defer client.Close()

	keyVersionName := *keyName
	if !strings.Contains(keyVersionName, "/cryptoKeyVersions/") {
		keyVersionName += "/cryptoKeyVersions/1"
	}

	importHash := sha256.Sum256(payload)

	req := &kmspb.AsymmetricSignRequest{
		Name: keyVersionName,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: importHash[:],
			},
		},
	}

	resp, err := client.AsymmetricSign(ctx, req)
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sigB64 := base64.RawURLEncoding.EncodeToString(resp.Signature)
	token := fmt.Sprintf("%s.%s", payloadB64, sigB64)
	fmt.Println(token)
}
