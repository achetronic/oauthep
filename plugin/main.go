// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// INTERFACE TO IMPLEMENT
// https://github.com/envoyproxy/envoy/blob/main/contrib/golang/common/go/api/filter.go
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

package main

import (
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	"oauthep/internal/config"
	"oauthep/internal/filter"
)

const Name = "oauthep"

func init() {
	http.RegisterHttpFilterFactoryAndConfigParser(Name, filter.NewStreamFilter, &config.ConfigParser{})
}

func main() {}
