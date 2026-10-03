# Nostr Guestbook container.
#   docker build -t nostr-guestbook .
#   docker run -p 8080:8080 -v nostr-guestbook:/data nostr-guestbook

# The SDK stage runs on the build machine's own platform and cross-compiles with -a. This is much
# faster than emulating arm64 under QEMU, and the app is managed code apart from SQLite, whose
# native library comes from the NuGet runtime pack for the target architecture.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
# Commit SHA for the version in the footer. .dockerignore leaves out .git, so it comes from
# outside: the GitHub workflow passes github.sha. Without it the app shows "development build".
ARG GIT_SHA=
WORKDIR /src

# Project files first: the restore layer stays cached while only source code changes.
# The lock file goes in with the project file, so the restore uses the pinned package build.
COPY src/NostrAuth/NostrAuth.csproj src/NostrAuth/packages.lock.json src/NostrAuth/
COPY app/NostrGuestbook/NostrGuestbook.csproj app/NostrGuestbook/
RUN dotnet restore app/NostrGuestbook/NostrGuestbook.csproj -a $TARGETARCH

COPY src/NostrAuth/ src/NostrAuth/
COPY app/NostrGuestbook/ app/NostrGuestbook/
RUN dotnet publish app/NostrGuestbook/NostrGuestbook.csproj -c Release -a $TARGETARCH --no-restore -o /out \
    -p:SourceRevisionId=$GIT_SHA
RUN mkdir /data

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app

# Database and Data Protection keys. Mount a volume here, or messages and logins are lost
# when the container is removed.
# The folder comes from the build stage: the final stage has no RUN, so an arm64 image
# builds on an amd64 machine without CPU emulation. 1654 is the aspnet image's "app" user.
ENV Guestbook__DataDirectory=/data
COPY --from=build --chown=1654:1654 /data /data
VOLUME /data

# The normal setup is a reverse proxy that ends TLS and talks plain http to this container. Without
# forwarded headers the app sees "http", and the login URL in the QR code and in the signed event
# says http:// while the user is on https://. This trusts X-Forwarded-For and X-Forwarded-Proto from
# any client, so publish the port to localhost or a private network only. Set it to false when the
# container is reachable directly.
ENV ASPNETCORE_FORWARDEDHEADERS_ENABLED=true

COPY --from=build /out .
# The base image's non-root user.
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "NostrGuestbook.dll"]
