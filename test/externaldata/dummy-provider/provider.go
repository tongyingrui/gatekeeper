package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	admissionv1 "k8s.io/api/admission/v1"
)

const (
	timeout    = 1 * time.Second
	apiVersion = "externaldata.gatekeeper.sh/v1alpha1"
)

func main() {
	fmt.Println("starting server...")

	// load Gatekeeper's CA certificate
	caCert, err := os.ReadFile("/tmp/gatekeeper/ca.crt")
	if err != nil {
		panic(err)
	}

	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(caCert)

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", processTimeout(validate, timeout))

	server := &http.Server{
		Addr:              ":8090",
		Handler:           mux,
		ReadHeaderTimeout: timeout,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientCAs,
			MinVersion: tls.VersionTLS13,
		},
	}

	if err := server.ListenAndServeTLS("/etc/ssl/certs/server.crt", "/etc/ssl/certs/server.key"); err != nil {
		panic(err)
	}
}

func validate(w http.ResponseWriter, req *http.Request) {
	// Log incoming request details
	log.Printf("Received %s request to /validate from %s", req.Method, req.RemoteAddr)
	log.Printf("Request headers: %v", req.Header)

	// only accept POST requests
	if req.Method != http.MethodPost {
		log.Printf("Rejecting non-POST request: %s", req.Method)
		sendResponse(nil, "only POST is allowed", w)
		return
	}

	// read request body
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		sendResponse(nil, fmt.Sprintf("unable to read request body: %v", err), w)
		return
	}

	// Log request body size in a friendly way
	bodySize := len(requestBody)
	log.Printf("📦 Received request body with %d bytes (%s)", bodySize, formatSize(bodySize))

	// Log raw request body for debugging
	log.Printf("Request body: %s", string(requestBody))

	// parse request body
	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		log.Printf("Error unmarshaling request body: %v", err)
		sendResponse(nil, fmt.Sprintf("unable to unmarshal request body: %v", err), w)
		return
	}

	// Log parsed request details
	log.Printf("Parsed request - Keys: %v", providerRequest.Request.Keys)
	log.Printf("Provider request details: APIVersion=%s, Kind=%s", providerRequest.APIVersion, providerRequest.Kind)

	results := make([]externaldata.Item, 0)
	// iterate over all keys
	for _, key := range providerRequest.Request.Keys {
		log.Printf("Processing key: %s", key)

		// Providers should add a caching mechanism to avoid extra calls to external data sources.
		admissionRequest, err := parseAdmissionRequest(key)
		if err != nil {
			log.Printf("Failed to parse admission request from key: %v", err)
			// If parsing fails, fall back to original behavior
			results = append(results, externaldata.Item{
				Key:   key,
				Error: "Failed to parse admission request",
			})
			continue
		}

		// Process the admission request
		result := processAdmissionRequest(key, admissionRequest)
		results = append(results, result)
	}
	sendResponse(&results, "", w)
}

// parseAdmissionRequest attempts to parse the key and extract the review field
func parseAdmissionRequest(key string) (*admissionv1.AdmissionRequest, error) {
	// First, parse the key as a generic map to extract the review field
	var keyData map[string]interface{}
	err := json.Unmarshal([]byte(key), &keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal key as JSON: %v", err)
	}

	// Extract the review field
	reviewData, exists := keyData["review"]
	if !exists {
		return nil, fmt.Errorf("no 'review' field found in key")
	}

	// Convert review data back to JSON and then unmarshal into AdmissionRequest
	reviewJSON, err := json.Marshal(reviewData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal review data: %v", err)
	}

	var admissionRequest admissionv1.AdmissionRequest
	err = json.Unmarshal(reviewJSON, &admissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal admission request: %v", err)
	}

	return &admissionRequest, nil
}

// processAdmissionRequest processes the parsed admission request and returns a result
func processAdmissionRequest(originalKey string, request *admissionv1.AdmissionRequest) externaldata.Item {
	// Add safety checks to prevent panics
	if request == nil {
		log.Printf("❌ Invalid admission request: request is nil")
		return externaldata.Item{
			Key:   originalKey,
			Error: "Invalid admission request: missing request data",
		}
	}

	// Safe access with nil checks
	namespace := "unknown"
	name := "unknown"
	kind := "unknown"
	operation := "unknown"

	if request.Namespace != "" {
		namespace = request.Namespace
	}
	if request.Name != "" {
		name = request.Name
	}
	if request.Kind.Kind != "" {
		kind = request.Kind.Kind
	}
	if string(request.Operation) != "" {
		operation = string(request.Operation)
	}

	log.Printf("Processing admission request for %s/%s of kind %s", namespace, name, kind)

	// Extract useful information from the admission review
	resourceInfo := fmt.Sprintf("Resource: %s/%s, Kind: %s, Operation: %s",
		namespace, name, kind, operation)

	log.Printf("Resource details: %s", resourceInfo)

	// Example processing logic - you can customize this based on your needs
	result := externaldata.Item{
		Key: originalKey,
	}

	// Check if this is a SolutionContainer (Symphony specific)
	if kind == "SolutionContainer" {
		log.Printf("Processing Symphony SolutionContainer")
		approved := checkSolutionContainerApproval(request)
		if approved {
			result.Value = "approved"
		} else {
			result.Error = "solution container requires approval"
		}
		return result
	}

	// Default: error other resources
	result.Error = "only Symphony SolutionContainer is supported Now"
	return result
}

// checkSolutionContainerApproval checks if a Symphony SolutionContainer should be approved
func checkSolutionContainerApproval(request *admissionv1.AdmissionRequest) bool {
	// Symphony-specific approval logic
	log.Printf("Checking Symphony SolutionContainer approval")

	// Check for required annotations or labels
	if request.Object.Raw != nil {
		var obj map[string]interface{}
		if err := json.Unmarshal(request.Object.Raw, &obj); err == nil {
			if metadata, ok := obj["metadata"].(map[string]interface{}); ok {
				if annotations, ok := metadata["annotations"].(map[string]interface{}); ok {

					// Check for Azure management additional properties
					if additionalPropsStr, exists := annotations["management.azure.com/additionalProperties"]; exists {
						if additionalPropsJSON, ok := additionalPropsStr.(string); ok {
							var additionalProps map[string]interface{}
							if err := json.Unmarshal([]byte(additionalPropsJSON), &additionalProps); err == nil {
								log.Printf("📋 Found additional properties: %v", additionalProps)

								// Check for yingruiapproved property
								if yingruiApproved, exists := additionalProps["yingruiapproved"]; exists {
									if approvedStr, ok := yingruiApproved.(string); ok {
										log.Printf("🔍 Found yingruiapproved: %s", approvedStr)
										// You can customize the approval logic here
										// For now, accepting any non-empty value as approval
										if approvedStr != "" && approvedStr != "false" {
											log.Printf("✅ SolutionContainer has yingruiapproved: %s", approvedStr)
											return true
										} else {
											log.Printf("❌ SolutionContainer yingruiapproved is false or empty")
										}
									} else {
										log.Printf("❌ yingruiapproved property is not a string: %v", yingruiApproved)
									}
								} else {
									log.Printf("❌ No yingruiapproved property found in additional properties")
								}
							} else {
								log.Printf("❌ Failed to parse additional properties JSON: %v", err)
							}
						} else {
							log.Printf("❌ additionalProperties annotation is not a string: %v", additionalPropsStr)
						}
					} else {
						log.Printf("❌ No management.azure.com/additionalProperties annotation found")
					}
				} else {
					log.Printf("❌ No annotations found in metadata")
				}
			} else {
				log.Printf("❌ No metadata found in object")
			}
		} else {
			log.Printf("❌ Failed to unmarshal request.Object.Raw: %v", err)
		}
	} else {
		log.Printf("❌ request.Object.Raw is nil")
	}

	// Default: require explicit approval
	log.Printf("❌ SolutionContainer approval not found or invalid")
	return false
}

// sendResponse sends back the response to Gatekeeper.
func sendResponse(results *[]externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
		Response: externaldata.Response{
			Idempotent: true,
		},
	}

	if results != nil {
		response.Response.Items = *results
	} else {
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
}

func processTimeout(h http.HandlerFunc, duration time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), duration)
		defer cancel()

		r = r.WithContext(ctx)

		processDone := make(chan bool)
		go func() {
			h(w, r)
			processDone <- true
		}()

		select {
		case <-ctx.Done():
			sendResponse(nil, "operation timed out", w)
		case <-processDone:
		}
	}
}

// formatSize formats byte size in a human-readable way
func formatSize(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
}
