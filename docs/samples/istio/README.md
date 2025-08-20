# OAuth2 Flow with Istio EnvoyFilter

This example shows you how to enable OAuth2 authentication in your applications using an Istio EnvoyFilter with Golang extensions.

## Prerequisites


### 1. Build and host your own Docker image

**⚠️ Important**: The official Istio Proxy image doesn't include extensions. You must create your own custom image.

1. Use the `Dockerfile` included in this directory
2. Build the image with OAuth extensions:
   ```bash
   docker build -t your-registry/istio-proxy-extensions:tag .
   ```
3. Push it to your registry (Docker Hub, GCR, ACR, etc.)


### 2. Configure your workload

Add these configurations to your Deployment/Pod:

#### Required labels:

```yaml
labels:
  sidecar.istio.io/inject: "true"
```

#### Required annotations:

Following annotations are needed to:

- Use your custom docker image with extensions inside
- Include a read-write volume for `/tmp` (JWKS cache is stored there)
- Load credentials that will be used by `client_secret` field in the EnvoyFilter object

```yaml
annotations:
  sidecar.istio.io/proxyImage: "your-registry/istio-proxy-extensions:tag"
  sidecar.istio.io/userVolume: |
    [
    {"name":"tmp-volume", "emptyDir":{}},
    {"name":"oauth-secrets", "secret":{"secretName":"credentials"}}
    ]
  sidecar.istio.io/userVolumeMount: |
    [
    {"name":"tmp-volume", "mountPath":"/tmp", "readonly":false},
    {"name":"oauth-secrets", "mountPath":"/etc/credentials.yaml", "subPath":"credentials.yaml", "readonly":true}
    ]
```

If you want to set credentials as plain text in the `EnvoyFilter` object (NOT recommended in production). It's
possible to use the following ones:

```yaml
annotations:
  sidecar.istio.io/proxyImage: "your-registry/istio-proxy-extensions:tag"
  sidecar.istio.io/userVolume: |
    [
    {"name":"tmp-volume", "emptyDir":{}}
    ]
  sidecar.istio.io/userVolumeMount: |
    [
    {"name":"tmp-volume", "mountPath":"/tmp", "readonly":false}
    ]
```

### 3. Configure and deploy your EnvoyFilter and enjoy

An example of the object that is needed is shown [here](envoyfilter.yaml). 

To know all the parameters you can configure, they are shown in the [Envoy example](../envoy/envoy-config-goext-complete.yaml)
