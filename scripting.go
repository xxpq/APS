package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
)

// ScriptRunner manages the execution of external scripts.
type ScriptRunner struct {
	config *ScriptingConfig
}

// ScriptData is the structure sent to and received from the script.
type ScriptData struct {
	Method     string      `json:"method,omitempty"`
	URL        string      `json:"url,omitempty"`
	Proto      string      `json:"proto,omitempty"`
	Headers    http.Header `json:"headers,omitempty"`
	Body       string      `json:"body,omitempty"`
	StatusCode int         `json:"statusCode,omitempty"`
	Status     string      `json:"status,omitempty"`
}

func NewScriptRunner(config *ScriptingConfig) *ScriptRunner {
	if config == nil {
		return &ScriptRunner{config: &ScriptingConfig{}}
	}
	return &ScriptRunner{config: config}
}

// RunOnRequest executes the onRequest script for a mapping.
func (s *ScriptRunner) RunOnRequest(req *http.Request, scriptPath string) (*http.Request, error) {
	if scriptPath == "" {
		return req, nil
	}

	// Convert request to JSON
	scriptData, err := s.requestToScriptData(req)
	if err != nil {
		return nil, err
	}

	// Run script
	modifiedData, err := s.runScript(scriptPath, scriptData)
	if err != nil {
		return nil, err
	}

	// Apply modifications back to the request
	return s.scriptDataToRequest(modifiedData, req)
}

// RunOnResponse executes the onResponse script for a mapping.
func (s *ScriptRunner) RunOnResponse(resp *http.Response, scriptPath string) (*http.Response, error) {
	if scriptPath == "" {
		return resp, nil
	}

	// Convert response to JSON
	scriptData, err := s.responseToScriptData(resp)
	if err != nil {
		return nil, err
	}

	// Run script
	modifiedData, err := s.runScript(scriptPath, scriptData)
	if err != nil {
		return nil, err
	}

	// Apply modifications back to the response
	return s.scriptDataToResponse(modifiedData, resp)
}

func (s *ScriptRunner) runScript(scriptPath string, data ScriptData) (ScriptData, error) {
	var cmd *exec.Cmd
	ext := filepath.Ext(scriptPath)

	switch ext {
	case ".py":
		if s.config.PythonPath == "" {
			return data, errors.New("python script path is not configured")
		}
		cmd = exec.Command(s.config.PythonPath, scriptPath)
	case ".js":
		if s.config.NodePath == "" {
			return data, errors.New("node script path is not configured")
		}
		cmd = exec.Command(s.config.NodePath, scriptPath)
	default:
		return data, errors.New("unsupported script type: " + ext)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return data, err
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return data, err
	}

	// Write data to stdin
	if err := json.NewEncoder(stdin).Encode(data); err != nil {
		return data, err
	}
	stdin.Close()

	if err := cmd.Wait(); err != nil {
		log.Printf("Script execution error for %s: %v\nStderr: %s", scriptPath, err, stderr.String())
		return data, err
	}

	// Decode modified data from stdout
	var modifiedData ScriptData
	if err := json.NewDecoder(&stdout).Decode(&modifiedData); err != nil {
		log.Printf("Error decoding script output for %s: %v", scriptPath, err)
		return data, err
	}

	return modifiedData, nil
}

func (s *ScriptRunner) requestToScriptData(r *http.Request) (ScriptData, error) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return ScriptData{}, err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore body

	return ScriptData{
		Method:  r.Method,
		URL:     r.URL.String(),
		Proto:   r.Proto,
		Headers: r.Header,
		Body:    string(bodyBytes),
	}, nil
}

func (s *ScriptRunner) scriptDataToRequest(data ScriptData, origReq *http.Request) (*http.Request, error) {
	newURL, err := origReq.URL.Parse(data.URL)
	if err != nil {
		return nil, err
	}

	newReq := origReq.WithContext(origReq.Context())
	newReq.Method = data.Method
	newReq.URL = newURL
	newReq.Proto = data.Proto
	newReq.Header = data.Headers
	newReq.Body = ioutil.NopCloser(strings.NewReader(data.Body))
	newReq.ContentLength = int64(len(data.Body))

	return newReq, nil
}

func (s *ScriptRunner) responseToScriptData(r *http.Response) (ScriptData, error) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return ScriptData{}, err
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore body

	return ScriptData{
		StatusCode: r.StatusCode,
		Status:     r.Status,
		Proto:      r.Proto,
		Headers:    r.Header,
		Body:       string(bodyBytes),
	}, nil
}

func (s *ScriptRunner) scriptDataToResponse(data ScriptData, origResp *http.Response) (*http.Response, error) {
	newResp := &http.Response{
		StatusCode: data.StatusCode,
		Status:     data.Status,
		Proto:      data.Proto,
		Header:     data.Headers,
		Body:       ioutil.NopCloser(strings.NewReader(data.Body)),
	}
	newResp.ContentLength = int64(len(data.Body))

	// Copy over unmodifiable fields
	newResp.Request = origResp.Request
	newResp.TLS = origResp.TLS

	return newResp, nil
}
