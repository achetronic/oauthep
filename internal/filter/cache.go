/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package filter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	//
	"oauthep/internal/validator"
)

type JwksCacheFile struct {
	JWKS      *validator.JWKS `json:"jwks"`
	Timestamp time.Time       `json:"timestamp"`
}

func (f *HttpFilter) getJwks() (*validator.JWKS, *time.Time, error) {

	ttlDur, err := time.ParseDuration(f.config.OauthJwksCacheTTL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parsing TTL for JWKS local cache")
	}

	// Try to read from file cache
	jwks, timestamp, err := f.readJwksFromFile(f.config.OauthJwksCacheFile)
	if err == nil && timestamp.After(time.Now().Add(-ttlDur)) {
		return jwks, &timestamp, nil
	}

	// Fetch from remote
	resp, err := http.Get(f.config.OauthJwksUri)
	if err != nil {
		return nil, nil, fmt.Errorf("failed getting JWKS from remote: %s", err.Error())
	}
	defer resp.Body.Close()

	jwksCerts := validator.JWKS{}
	err = json.NewDecoder(resp.Body).Decode(&jwksCerts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed decoding JWKS from remote: %s", err.Error())
	}

	jwksCertsAt := time.Now()

	// Save to file cache
	err = f.writeJwksToFile(f.config.OauthJwksCacheFile, &jwksCerts, jwksCertsAt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed writing in fs: %s", err.Error())
	}

	return &jwksCerts, &jwksCertsAt, nil
}

func (f *HttpFilter) readJwksFromFile(filename string) (*validator.JWKS, time.Time, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer file.Close()

	// Lock for reading
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_SH) // Shared lock
	if err != nil {
		return nil, time.Time{}, err
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, time.Time{}, err
	}

	var cache JwksCacheFile
	err = json.Unmarshal(data, &cache)
	if err != nil {
		return nil, time.Time{}, err
	}

	return cache.JWKS, cache.Timestamp, nil
}

// writeJwksToFile TODO
func (f *HttpFilter) writeJwksToFile(filename string, jwks *validator.JWKS, timestamp time.Time) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("failed creating cache directory: %v", err)
	}

	// Open/create file for writing
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed opening cache file: %v", err)
	}
	defer file.Close()

	// Exclusive lock for writing
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
	if err != nil {
		return fmt.Errorf("failed locking cache file: %v", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	cache := JwksCacheFile{
		JWKS:      jwks,
		Timestamp: timestamp,
	}

	data, err := json.Marshal(cache)
	if err != nil {
		return fmt.Errorf("failed marshaling cache: %v", err)
	}

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed writing cache file: %v", err)
	}

	return nil
}
