package utils

import (
	"bytes"
	"encoding/base64"
	"fmt"

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
