# Builds and runs HkdfGuard's unit tests on Linux.
#
# Build: docker build -t hkdfguard-tests .
# Run:   docker run --rm --security-opt seccomp=unconfined hkdfguard-tests
#
# This image deliberately does NOT install systemd - a container should never have a real
# systemd managing /run/credentials, so LinuxSystemdStorageTests.
# CreateOrGet_UsingKernelKeyring_PersistsAndReturnsSameMaterial is the only LinuxSystemdStorage
# test that runs here, exercising just the Linux kernel keyring (add_key/keyctl_read) that every
# container can actually use. libkeyutils1 provides that syscall wrapper.
# CreateOrGet_UsingSystemdCreds_PersistsAndReturnsSameMaterial exercises the systemd-creds path
# instead - it skips itself here (no /run/credentials) and is only meant to run for real on a
# genuine systemd-managed Linux server, outside a container, not in this image.
#
# --security-opt seccomp=unconfined is required at `docker run` time (it cannot be baked into
# the image): Docker's default seccomp profile blocks the add_key syscall the kernel-keyring
# test needs. Without it, every test passes except
# CreateOrGet_UsingKernelKeyring_PersistsAndReturnsSameMaterial, which fails with
# "add_key failed: 1" (EPERM) - a container-sandboxing artifact, not a code or test bug.
FROM mcr.microsoft.com/dotnet/sdk:10.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends libkeyutils1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN dotnet restore HkdfGuard.sln
RUN dotnet build HkdfGuard.sln --configuration Release --no-restore

ENTRYPOINT ["dotnet", "test", "HkdfGuard.sln", "--configuration", "Release", "--no-build"]
