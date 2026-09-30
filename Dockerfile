# Nostr Guestbook container.
#   docker build -t nostr-guestbook .
#   docker run -p 8080:8080 -v nostr-guestbook:/data nostr-guestbook

# The SDK stage runs on the build machine's own platform and cross-compiles with -a. This is much
# faster than emulating arm64 under QEMU, and the app is managed code apart from SQLite, whose
# native library comes from the NuGet runtime pack for the target architecture.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
WORKDIR /src

# Project files first: the restore layer stays cached while only source code changes.
COPY src/NostrAuth/NostrAuth.csproj src/NostrAuth/
COPY app/NostrGuestbook/NostrGuestbook.csproj app/NostrGuestbook/
RUN dotnet restore app/NostrGuestbook/NostrGuestbook.csproj -a $TARGETARCH

COPY src/NostrAuth/ src/NostrAuth/
COPY app/NostrGuestbook/ app/NostrGuestbook/
RUN dotnet publish app/NostrGuestbook/NostrGuestbook.csproj -c Release -a $TARGETARCH --no-restore -o /out
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

COPY --from=build /out .
# The base image's non-root user.
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "NostrGuestbook.dll"]
