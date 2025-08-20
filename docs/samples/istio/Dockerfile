# Default versions for building
# 1. Oauthep Docker images have several .so binaries to support different Envoy versions per release
#    Just check if the desired Oauthep version includes the .so for the Envoy you want. Open PR if not. Contribute!
ARG ISTIO_VERSION=1.26.2
ARG OAUTHEP_VERSION=v0.1.0

#############################################
## Extensions: Oauthep
#############################################

FROM ghcr.io/achetronic/oauthep:${OAUTHEP_VERSION}-${TARGETARCH} as oauthep_source

#############################################
## Base: Istio Proxy
#############################################

FROM docker.io/istio/proxyv2:${ISTIO_VERSION}

# Create final directory when missing
USER root
RUN mkdir -p /extensions && \
    chown -R istio-proxy:istio-proxy /extensions

# Copy plugins from other layers
# Hey, SRE! If you need to add more plugins in the future, this is the right place
COPY --from=oauthep_source /liboauthep*.so /extensions/

# Set proper permissions for .so files
RUN chmod 755 /extensions/*.so && \
    chown istio-proxy:istio-proxy /extensions/*.so

USER istio-proxy
