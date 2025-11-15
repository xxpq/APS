package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	reflectpb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
)

// handleRestToGrpc handles the conversion of a RESTful HTTP request to a gRPC call.
func (p *MapRemoteProxy) handleRestToGrpc(w http.ResponseWriter, r *http.Request, mapping *Mapping) {
	// 1. Build the gRPC request message as a map from the HTTP request.
	grpcRequestMap, err := p.buildGrpcRequestMap(r, mapping)
	if err != nil {
		log.Printf("[REST-to-gRPC] Error building request map: %v", err)
		http.Error(w, fmt.Sprintf("Error building gRPC request: %v", err), http.StatusBadRequest)
		return
	}

	log.Printf("[REST-to-gRPC] Built request map: %+v", grpcRequestMap)

	// --- gRPC Dynamic Invocation ---
	fromConfig := mapping.GetFromConfig()
	toURL, err := url.Parse(mapping.GetToURL())
	if err != nil {
		http.Error(w, "Invalid 'to' URL for gRPC backend", http.StatusInternalServerError)
		return
	}

	grpcService := fromConfig.GRPC.Service
	grpcMethod := fromConfig.GRPC.Method
	grpcBackend := toURL.Host // e.g., "localhost:50051"

	// 2. Connect to the backend gRPC server.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, grpcBackend, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Printf("[REST-to-gRPC] Failed to connect to gRPC backend %s: %v", grpcBackend, err)
		http.Error(w, "Failed to connect to gRPC backend", http.StatusBadGateway)
		return
	}
	defer conn.Close()

	// 3. Use reflection to get method descriptor.
	refClient := grpcreflect.NewClient(ctx, reflectpb.NewServerReflectionClient(conn))
	svcDesc, err := refClient.ResolveService(grpcService)
	if err != nil {
		log.Printf("[REST-to-gRPC] Failed to resolve service %s: %v", grpcService, err)
		http.Error(w, fmt.Sprintf("gRPC service '%s' not found or reflection not enabled", grpcService), http.StatusNotFound)
		return
	}
	mtdDesc := svcDesc.FindMethodByName(grpcMethod)
	if mtdDesc == nil {
		log.Printf("[REST-to-gRPC] Failed to find method %s in service %s", grpcMethod, grpcService)
		http.Error(w, fmt.Sprintf("gRPC method '%s' not found in service '%s'", grpcMethod, grpcService), http.StatusNotFound)
		return
	}

	// 4. Create a dynamic message and unmarshal the map into it.
	reqMsg := dynamic.NewMessage(mtdDesc.GetInputType())
	reqJsonBytes, _ := json.Marshal(grpcRequestMap)
	if err := reqMsg.UnmarshalJSON(reqJsonBytes); err != nil {
		log.Printf("[REST-to-gRPC] Failed to unmarshal map to dynamic message: %v", err)
		http.Error(w, "Failed to construct gRPC request message", http.StatusInternalServerError)
		return
	}

	// 5. Make the gRPC call.
	stub := grpcdynamic.NewStub(conn)
	respMsg, err := stub.InvokeRpc(ctx, mtdDesc, reqMsg)
	if err != nil {
		log.Printf("[REST-to-gRPC] gRPC call failed: %v", err)
		// TODO: Translate gRPC error codes to HTTP status codes
		http.Error(w, fmt.Sprintf("gRPC call failed: %v", err), http.StatusBadGateway)
		return
	}

	// 6. Translate the gRPC response back to an HTTP response.
	respJson, err := json.Marshal(respMsg)
	if err != nil {
		log.Printf("[REST-to-gRPC] Failed to marshal gRPC response to JSON: %v", err)
		http.Error(w, "Failed to process gRPC response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respJson)

	log.Printf("[REST-to-gRPC] Successfully converted REST request to gRPC call for %s/%s", grpcService, grpcMethod)
}

// buildGrpcRequestMap constructs a map representing the gRPC request message
// by extracting data from the HTTP request based on the mapping configuration.
func (p *MapRemoteProxy) buildGrpcRequestMap(r *http.Request, mapping *Mapping) (map[string]interface{}, error) {
	config := mapping.GetFromConfig().GRPC.RestToGrpc
	if config == nil || len(config.RequestBodyMapping) == 0 {
		return nil, fmt.Errorf("RestToGrpc config or RequestBodyMapping is missing")
	}

	resultMap := make(map[string]interface{})

	// --- Data Sources ---
	// 1. JSON Body
	var jsonBody map[string]interface{}
	if r.Body != nil && strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		// Restore the body so it can be read again if needed
		r.Body = ioutil.NopCloser(strings.NewReader(string(bodyBytes)))
		if len(bodyBytes) > 0 {
			if err := json.Unmarshal(bodyBytes, &jsonBody); err != nil {
				return nil, fmt.Errorf("failed to unmarshal JSON body: %w", err)
			}
		}
	}

	// 2. Query Parameters
	queryParams := r.URL.Query()

	// 3. Path Parameters (using gorilla/mux for parsing)
	pathParams, err := p.extractPathParams(r, mapping)
	if err != nil {
		return nil, fmt.Errorf("failed to extract path parameters: %w", err)
	}

	// --- Mapping ---
	for grpcField, httpSource := range config.RequestBodyMapping {
		parts := strings.SplitN(httpSource, ":", 2)
		if len(parts) != 2 {
			log.Printf("[REST-to-gRPC] Invalid mapping format for field '%s': %s", grpcField, httpSource)
			continue
		}
		sourceType, sourceName := parts[0], parts[1]
		var value interface{}
		found := false

		switch sourceType {
		case "json":
			if jsonBody != nil {
				value, found = jsonBody[sourceName]
			}
		case "query":
			if val, ok := queryParams[sourceName]; ok && len(val) > 0 {
				value = val[0] // Take the first value
				found = true
			}
		case "path":
			if val, ok := pathParams[sourceName]; ok {
				value = val
				found = true
			}
		default:
			log.Printf("[REST-to-gRPC] Unsupported source type '%s' for field '%s'", sourceType, grpcField)
			continue
		}

		if found {
			if err := setNestedMapValue(resultMap, grpcField, value); err != nil {
				log.Printf("[REST-to-gRPC] Failed to set value for field '%s': %v", grpcField, err)
			}
		}
	}

	return resultMap, nil
}

// extractPathParams uses a temporary gorilla/mux router to parse path variables.
func (p *MapRemoteProxy) extractPathParams(r *http.Request, mapping *Mapping) (map[string]string, error) {
	// The "from" URL in the mapping is used as the template
	fromURL := mapping.GetFromURL()
	parsedFrom, err := url.Parse(fromURL)
	if err != nil {
		return nil, fmt.Errorf("invalid 'from' URL in mapping: %w", err)
	}

	// Mux router needs the path in the format /path/{var}, not the full URL
	router := mux.NewRouter()
	route := router.NewRoute()
	route.Path(parsedFrom.Path)

	var match mux.RouteMatch
	if route.Match(r, &match) {
		return match.Vars, nil
	}

	return make(map[string]string), nil // No match, no params
}

// setNestedMapValue sets a value in a nested map based on a dot-separated path.
func setNestedMapValue(data map[string]interface{}, path string, value interface{}) error {
	keys := strings.Split(path, ".")
	currentMap := data

	for i, key := range keys {
		if i == len(keys)-1 {
			// Last key, set the value
			currentMap[key] = value
		} else {
			// Not the last key, traverse or create nested map
			if next, ok := currentMap[key]; ok {
				if nextMap, ok := next.(map[string]interface{}); ok {
					currentMap = nextMap
				} else {
					return fmt.Errorf("key '%s' in path '%s' is not a map", key, path)
				}
			} else {
				newMap := make(map[string]interface{})
				currentMap[key] = newMap
				currentMap = newMap
			}
		}
	}
	return nil
}
