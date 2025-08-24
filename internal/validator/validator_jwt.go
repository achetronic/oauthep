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

package validator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	//
	"github.com/golang-jwt/jwt/v5"
)

// JWKS represents a set (group) of several JWK
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represent a single JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`

	N string `json:"n,omitempty"` // RSA modulus
	E string `json:"e,omitempty"` // RSA exponent

	Crv string `json:"crv,omitempty"` // EC curve
	X   string `json:"x,omitempty"`   // EC x coordinate
	Y   string `json:"y,omitempty"`   // EC y coordinate

	K   string `json:"k,omitempty"` // Symmetric key (for HMAC)
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// IsParsableAsJWT return true when the string has a valid JWT structure
func IsParsableAsJWT(tokenString string) bool {
	_, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	return err == nil
}

func ValidateJsonWebToken(jwks *JWKS, token string) (*jwt.Token, error) {

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {

		// 1. Look for the key in JWKS the JWT was signed with
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("jwt header 'kid' field not found")
		}

		//
		var matchingKey *JWK
		for _, key := range jwks.Keys {
			if key.Kid == kid && (key.Use == "" || key.Use == "sig") {
				matchingKey = &key
				break
			}
		}

		if matchingKey == nil {
			return nil, fmt.Errorf("no matching 'kid' in JWKS")
		}

		// 2. Verify the signature algorithm matching between the JWT and the JWKS
		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("jwt header 'alg' field not found")
		}

		//
		if matchingKey.Alg != "" && matchingKey.Alg != alg {
			return nil, fmt.Errorf("algorithm mismatch")
		}

		// Review whether signing algorithm is supported in our side.
		// Remember we later translate JWK to a PublicKey and we don't support all the existing algorithms for that.
		expectedMethod, err := getSigningMethod(alg)
		if err != nil {
			return nil, err
		}

		if token.Method != expectedMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", alg)
		}

		// Convert the JWK to PublicKey
		publicKey, err := jwkToPublicKey(matchingKey)
		if err != nil {
			return nil, fmt.Errorf("error converting JWK to public key: %v", err)
		}

		return publicKey, nil
	})

	return parsedToken, err
}

// jwkToPublicKey calculate corresponding real key (RSA, EC, etc.) from params present in the JWK
func jwkToPublicKey(jwk *JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return jwkToRSAPublicKey(jwk)
	case "EC":
		return jwkToECPublicKey(jwk)
	case "oct": // Symmetric keys
		return jwkToSymmetricKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// jwkToRSAPublicKey converts a JWK into a public RSA key
func jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("incomplete RSA key data")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("error decoding modulus: %v", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("error decoding exponent: %v", err)
	}

	n := new(big.Int)
	n.SetBytes(nBytes)

	var e int
	for i := 0; i < len(eBytes); i++ {
		e = e<<8 + int(eBytes[i])
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// jwkToECPublicKey converts a JWK into a public ECDSA key
func jwkToECPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.X == "" || jwk.Y == "" || jwk.Crv == "" {
		return nil, fmt.Errorf("incomplete EC key data")
	}

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("error decoding X coordinate: %v", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("error decoding Y coordinate: %v", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// jwkToSymmetricKey converts a JWK into a symmetric key (for HMAC)
func jwkToSymmetricKey(jwk *JWK) ([]byte, error) {
	if jwk.K == "" {
		return nil, fmt.Errorf("incomplete symmetric key data")
	}

	k, err := base64.RawURLEncoding.DecodeString(jwk.K)
	if err != nil {
		return nil, fmt.Errorf("error decoding symmetric key: %v", err)
	}

	return k, nil
}

// getSigningMethod returns suitable signing method according to the algorithm
func getSigningMethod(alg string) (jwt.SigningMethod, error) {
	switch alg {
	case "RS256":
		return jwt.SigningMethodRS256, nil
	case "RS384":
		return jwt.SigningMethodRS384, nil
	case "RS512":
		return jwt.SigningMethodRS512, nil
	case "ES256":
		return jwt.SigningMethodES256, nil
	case "ES384":
		return jwt.SigningMethodES384, nil
	case "ES512":
		return jwt.SigningMethodES512, nil
	case "HS256":
		return jwt.SigningMethodHS256, nil
	case "HS384":
		return jwt.SigningMethodHS384, nil
	case "HS512":
		return jwt.SigningMethodHS512, nil
	default:
		return nil, fmt.Errorf("unsupported signing method: %s", alg)
	}
}
