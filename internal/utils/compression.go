// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

	//
	"github.com/andybalholm/brotli"
)

func CompressBrotli(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	br := brotli.NewWriterLevel(&buf, brotli.BestCompression)
	if _, err := br.Write(data); err != nil {
		return nil, err
	}
	if err := br.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func CompressBrotliBase64(input string) (string, error) {

	// Decode base64
	data, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("error decoding base64: %w", err)
	}

	// Compress
	compressed, err := CompressBrotli(data)
	if err != nil {
		return "", fmt.Errorf("error compressing with brotli: %w", err)
	}

	// Re-encode in base64
	return base64.RawURLEncoding.EncodeToString(compressed), nil
}

func CompressJWT(jwt string) (string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	compressedHeader, err := CompressBrotliBase64(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed compressing header: %w", err)
	}

	compressedPayload, err := CompressBrotliBase64(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed compressing payload: %w", err)
	}

	return fmt.Sprintf("%s.%s.%s", compressedHeader, compressedPayload, parts[2]), nil
}

func DecompressBrotli(compressed []byte) ([]byte, error) {
	buf := bytes.NewReader(compressed)
	br := brotli.NewReader(buf)

	var result bytes.Buffer
	if _, err := result.ReadFrom(br); err != nil {
		return nil, err
	}

	return result.Bytes(), nil
}

func DecompressBrotliBase64(input string) (string, error) {
	//
	compressed, err := base64.RawURLEncoding.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("error decoding base64: %w", err)
	}

	//
	data, err := DecompressBrotli(compressed)
	if err != nil {
		return "", fmt.Errorf("error decompressing with brotli: %w", err)
	}

	//
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func DecompressJWT(compressedJWT string) (string, error) {
	parts := strings.Split(compressedJWT, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid compressed JWT format")
	}

	decompressedHeader, err := DecompressBrotliBase64(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed decompressing header: %w", err)
	}

	decompressedPayload, err := DecompressBrotliBase64(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed decompressing payload: %w", err)
	}

	return fmt.Sprintf("%s.%s.%s", decompressedHeader, decompressedPayload, parts[2]), nil
}
