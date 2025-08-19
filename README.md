# Oauthep (Oauth2 Envoy Plugin)

![GitHub Release](https://img.shields.io/github/v/release/achetronic/tnep)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/achetronic/tnep)
[![Go Report Card](https://goreportcard.com/badge/github.com/achetronic/tnep)](https://goreportcard.com/report/github.com/achetronic/tnep)
![GitHub License](https://img.shields.io/github/license/achetronic/tnep)

![GitHub User's stars](https://img.shields.io/github/stars/achetronic?label=Achetronic%20Stars)
![GitHub followers](https://img.shields.io/github/followers/achetronic?label=Achetronic%20Followers)

> [!IMPORTANT]  
> This is a Go extension plugin for Envoy Proxy using the native Golang filter support.
> [How it works](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/golang_filter)

## Description

Envoy Go extension plugin that provides complete OAuth2/OpenID Connect authentication flow for your services.
It handles authentication, token validation, session management, and integrates seamlessly with any OAuth2/OIDC provider 
like Keycloak, Auth0, or Google.

## Motivation

Modern microservices need robust authentication, but implementing OAuth2 flows in every service is repetitive and error-prone.

Many teams end up with inconsistent auth implementations across services, or rely on complex external auth services 
that add latency and complexity.

This plugin moves OAuth2 authentication to the proxy layer, giving you less maintenance and peace of mind.

If you want bulletproof OAuth2 authentication at the proxy level without the overhead of external auth services, 
this is the plugin you're looking for.

## Features

- **Complete OAuth2/OIDC flow**: Authorization code flow
- **JWT token validation**: Automatic JWKS fetching and caching
- **Session management**: Secure session cookies with configurable duration
- **Flexible routing**: Skip authentication for specific paths (health checks, static assets)
- **Multiple secret sources**: Literal values, environment variables, or SDS (Secret Discovery Service)
- **Comprehensive logging**: JSON structured logs with configurable verbosity
- **Multi-provider support**: Works with Keycloak, Auth0, Google, AWS Cognito, and any OIDC provider
- **Cookie content compression**: For companies with roles/groups inside JWT, cookie content is compressed with Brotli

## How to deploy

The deployment process depends on your target environment (Istio or pure Envoy). 
You can find complete examples for both scenarios in the [documentation directory](./docs/samples).

> [!IMPORTANT]
> Remember that Envoy version must match to the version this plugin is compiled for. Because of that, we compile
> the plugin for several ones. Choose wisely. [Official Envoy docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/golang_filter#developing-a-go-plugin)

## How to develop

This plugin is developed using Go with Envoy's native Golang extension support.

To get started:

```console
# Build the plugin
make build

# Run Envoy with the plugin for testing
make run

# Build for all supported Envoy versions
make build-all
```

As we compile the plugin for several Envoy versions, we develop targeting the oldest one to be everything is working
fine for everyone.

## How releases are created

Each release is completely automated using [Github Actions' workflows](./github).

The build process uses recipes from the Makefile to ensure transparency and reproducibility.

Assets for each version include:

Compiled .so files for each supported Envoy version
Docker images with all plugin variants
Complete documentation and examples


## How to collaborate

We are open to external collaborations for this project. For doing it you must:
- Open an issue explaining the problem
- Fork the repository 
- Make your changes to the code
- Open a PR 

> We are developers and hate bad code. For that reason we ask you the highest quality on each line of code to improve
> this project on each iteration. The code will always be reviewed and tested

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Special mention

This project was done using IDEs from JetBrains. They helped us to develop faster, so we recommend them a lot! 🤓

<img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_beam.png" alt="JetBrains Logo (Main) logo." width="150">