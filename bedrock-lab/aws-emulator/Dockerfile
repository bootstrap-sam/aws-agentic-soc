# AWS publishes no prebuilt image for macOS/Windows; this follows
# https://docs.aws.amazon.com/emulator/latest/userguide/getting-started-docker.html
# but uses the full amazonlinux:2023 base: the -minimal tag from the docs ships
# microdnf, which fails with "No package matches '/tmp/aws-emulator.rpm'".
FROM public.ecr.aws/amazonlinux/amazonlinux:2023
# Set automatically by BuildKit: amd64 or arm64.
ARG TARGETARCH
RUN case "$TARGETARCH" in arm64) A=aarch64 ;; amd64|"") A=x86_64 ;; *) echo "unsupported $TARGETARCH"; exit 1 ;; esac \
 && curl -fsSL -o /tmp/aws-emulator.rpm "https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/latest/aws-emulator-$A.rpm" \
 && dnf install -y /tmp/aws-emulator.rpm && dnf clean all && rm /tmp/aws-emulator.rpm
EXPOSE 9297
ENTRYPOINT ["aws-emulator", "-b", "0.0.0.0"]
