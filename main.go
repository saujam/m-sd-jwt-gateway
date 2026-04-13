package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/saujam/m-sd-jwt-gateway/merkle"
)

func main() {
	http.HandleFunc("/scim/Users", scimHandler)

	fmt.Println("🚀 M-SD-JWT SCIM-DI Gateway running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func scimHandler(w http.ResponseWriter, r *http.Request) {
	// Demo high-cardinality attributes (in real app, load from your SCIM backend)
	attributes := []string{
		"role:admin", "role:user", "group:engineering", "group:finance",
		"entitlement:cloud-storage", "entitlement:email", /* ... add more */
	}

	tree := merkle.NewTree(attributes)
	rootHash := tree.RootHash()

	// Create signed JWT with Merkle root
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":         "https://idp.example.com",
		"sub":         "user123",
		"merkle_root": rootHash,
		"tree_depth":  17,
		"iat":         1744480000,
		"exp":         1744566400,
	})
	signedToken, _ := token.SignedString([]byte("your-secret-key-change-in-production"))

	// Return paginated response
	response := map[string]interface{}{
		"merkle_root": signedToken,
		"attributes":  attributes[0:10], // first page (demo)
		"proof":       tree.GetProof(0, 10),
		"cursor":      "eyJzdGFydCI6MTB9", // base64 cursor example
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}