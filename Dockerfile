# Dockerfile for building "compact" image.
# This image is intended to be used with ImageVolumeMount in Kubernetes
# Ref: https://kubernetes.io/docs/tasks/configure-pod-container/image-volumes/

FROM scratch

ARG DIST_DIR=dist
COPY ${DIST_DIR}/ ./