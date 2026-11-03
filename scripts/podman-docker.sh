#!/bin/sh
# Docker's command line, as far as wrangler uses it, over Podman, for `wrangler dev` and
# `wrangler deploy` (npm run dev and npm run deploy set it up), or by hand:
#
#   WRANGLER_DOCKER_BIN="$PWD/scripts/podman-docker.sh" npx wrangler deploy
#
# build: `podman build` lacks the buildx flags wrangler passes (--load, --provenance), and cannot
#   read a Dockerfile from a piped standard input (`-f -`), so the Dockerfile goes through a
#   temporary file.
#
# push, then `image inspect --format '{{ json .RepoDigests }}'`: wrangler deploys the image by the
#   digest the registry gave it, which it reads from RepoDigests after the push. Docker lists there
#   what registries have confirmed. Podman lists a digest of the local copy for every name the
#   image has, and that changes when the layers are compressed for upload, so the registry holds
#   no image under it (IMAGE_REGISTRY_DOESNT_CONTAIN_IMAGE). The digest the push really produced
#   is recorded and given as the answer instead.
#
# Without a systemd user session, Podman must manage cgroups itself.

# Docker's image format, which is what wrangler otherwise hands to the registry.
export BUILDAH_FORMAT=docker

podman() {
  if [ -z "$DBUS_SESSION_BUS_ADDRESS" ]; then
    command podman --cgroup-manager=cgroupfs "$@"
  else
    command podman "$@"
  fi
}

# Where pushed digests are kept between wrangler's separate invocations of this script.
pushed="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/podman-docker-$(id -u)"

# The file a pushed image reference's digest is recorded in.
record() {
  printf '%s/%s' "$pushed" "$(printf '%s' "$1" | cksum | tr ' ' '-')"
}

if [ "$1" = push ] && [ "$#" -eq 2 ]; then
  mkdir -p "$pushed" && chmod 700 "$pushed"
  file=$(record "$2")
  rm -f "$file"
  podman push --digestfile "$file" "$2"
  status=$?
  [ "$status" -eq 0 ] || rm -f "$file"
  exit $status
fi

if [ "$1" = image ] && [ "$2" = inspect ] && [ "$4" = --format ]; then
  file=$(record "$3")
  case $5 in
    *RepoDigests*)
      if [ -s "$file" ]; then
        # The reference without its tag; a colon before the last slash is a port.
        repository=${3%@*}
        case ${repository##*/} in
          *:*) repository=${repository%:*} ;;
        esac
        printf '["%s@%s"]\n' "$repository" "$(cat "$file")"
        exit 0
      fi
      ;;
  esac
fi

if [ "$1" != build ]; then
  podman "$@"
  exit $?
fi
shift
dockerfile=
file_follows=
for arg do
  shift
  if [ -n "$file_follows" ]; then
    file_follows=
    if [ "$arg" = - ]; then
      dockerfile=$(mktemp)
      cat > "$dockerfile"
      arg=$dockerfile
    fi
    set -- "$@" "$arg"
    continue
  fi
  case "$arg" in
    --load | --provenance=*) ;;
    -f | --file) file_follows=1; set -- "$@" "$arg" ;;
    *) set -- "$@" "$arg" ;;
  esac
done
podman build "$@"
status=$?
[ -n "$dockerfile" ] && rm -f "$dockerfile"
exit $status
