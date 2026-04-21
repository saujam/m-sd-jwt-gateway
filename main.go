package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/saujam/m-sd-jwt-gateway/merkle"
)

// pageSize is the default number of attributes per page
const defaultPageSize = 10

func main() {
	http.HandleFunc("/scim/Users", scimHandler)
	http.HandleFunc("/health", healthHandler)
	fmt.Println("🚀 M-SD-JWT SCIM-DI Gateway running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// healthHandler provides a simple liveness probe
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func scimHandler(w http.ResponseWriter, r *http.Request) {
	// --- Parse cursor (base64-encoded start index) ---
	startIndex := 0
	if cursorParam := r.URL.Query().Get("cursor"); cursorParam != "" {
		decoded, err := base64.StdEncoding.DecodeString(cursorParam)
		if err == nil {
			if idx, err := strconv.Atoi(string(decoded)); err == nil && idx >= 0 {
				startIndex = idx
			}
		}
	}

	// --- Parse page size ---
	pageSize := defaultPageSize
	if countParam := r.URL.Query().Get("count"); countParam != "" {
		if n, err := strconv.Atoi(countParam); err == nil && n > 0 && n <= 1000 {
			pageSize = n
		}
	}

	// Demo high-cardinality attributes (in production, load from your SCIM backend)
	attributes := []string{
		"role:admin", "role:user", "group:engineering", "group:finance",
		"entitlement:cloud-storage", "entitlement:email",
		"entitlement:vpn", "entitlement:ci-cd", "entitlement:monitoring",
		"entitlement:billing", "entitlement:audit-logs", "entitlement:export",
	}

	totalAttributes := len(attributes)

	// --- Bounds check: clamp startIndex ---
	if startIndex >= totalAttributes {
		startIndex = totalAttributes
	}

	// --- Compute end index safely ---
	endIndex := startIndex + pageSize
	if endIndex > totalAttributes {
		endIndex = totalAttributes
	}

	// --- Build Merkle tree over ALL attributes (integrity over full set) ---
	tree := merkle.NewTree(attributes)
	rootHash := tree.RootHash()

	// --- Build signed JWT with Merkle root ---
	signingSecret := os.Getenv("JWT_SECRET")
	if signingSecret == "" {
		signingSecret = "change-me-in-production-use-env-var"
		log.Println("WARNING: JWT_SECRET not set — using insecure default")
	}

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":         "https://idp.example.com",
		"sub":         "user123",
		"merkle_root": rootHash,
		"tree_depth":  tree.Depth(),
		"total_attrs": totalAttributes,
		"iat":         now.Unix(),
		"exp":         now.Add(24 * time.Hour).Unix(),
	})

	signedToken, err := token.SignedString([]byte(signingSecret))
	if err != nil {
		http.Error(w, `{"error":"failed to sign token"}`, http.StatusInternalServerError)
		log.Printf("JWT signing error: %v", err)
		return
	}

	// --- Get Merkle proof for the requested page ---
	proof := tree.GetProof(startIndex, endIndex)

	// --- Build next cursor (nil if last page) ---
	var nextCursor *string
	if endIndex < totalAttributes {
		encoded := base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(endIndex)))
		nextCursor = &encoded
	}

	// --- Compose response ---
	response := map[string]interface{}{
		"merkle_root":      signedToken,
		"attributes":       attributes[startIndex:endIndex],
		"proof":            proof,
		"start_index":      startIndex,
		"page_size":        endIndex - startIndex,
		"total_attributes": totalAttributes,
		"next_cursor":      nextCursor,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("JSON encode error: %v", err)
	}
}
