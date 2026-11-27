#!/usr/bin/env bash
# Stage under each release run's immutable tags so rerunning that run can resume partial publication.
set -euo pipefail

digest() {
    docker buildx imagetools inspect "$1" --format '{{json .Manifest}}' |
        python3 -c 'import json, re, sys
value = json.load(sys.stdin)["digest"]
if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
    raise SystemExit("invalid OCI manifest digest")
print(value)'
}

pull_checked() {
    local reference=$1 revision=$2 source_url=$3
    docker pull "$reference" >&2
    docker image inspect "$reference" --format '{{json .Config.Labels}}' |
        python3 -c 'import json, sys
labels = json.load(sys.stdin) or {}
if labels.get("org.opencontainers.image.revision") != sys.argv[1] or labels.get("org.opencontainers.image.source") != sys.argv[2]:
    raise SystemExit("the staged image names another source or revision")' "$revision" "$source_url"
}

case "$1" in
    restore)
        if staged=$(digest "$3" 2>/dev/null); then
            reference="${3%:*}@$staged"
            pull_checked "$reference" "$4" "$5"
            docker tag "$reference" "$2"
        fi
        ;;
    stage)
        source_image=$2
        staging_tag=$3
        if ! staged=$(digest "$staging_tag" 2>/dev/null); then
            docker tag "$source_image" "$staging_tag"
            docker push "$staging_tag"
            staged=$(digest "$staging_tag")
        fi
        reference="${staging_tag%:*}@$staged"
        pull_checked "$reference" "$4" "$5"
        checked_id=$(docker image inspect "$source_image" --format '{{.Id}}')
        staged_id=$(docker image inspect "$reference" --format '{{.Id}}')
        if [ "$checked_id" != "$staged_id" ]; then
            echo "The staged image differs from the one this job tested" >&2
            exit 1
        fi
        ;;
    promote)
        repository=$2
        release_tag=$3
        run=$4
        stage="$repository:$release_tag-index-run-$run"
        final="$repository:$release_tag"
        amd64=$(digest "$repository:$release_tag-amd64-run-$run")
        arm64=$(digest "$repository:$release_tag-arm64-run-$run")
        if ! staged=$(digest "$stage" 2>/dev/null); then
            docker buildx imagetools create --tag "$stage" "$repository@$amd64" "$repository@$arm64" >&2
            staged=$(digest "$stage")
        fi
        docker buildx imagetools inspect "$repository@$staged" --raw |
            python3 -c 'import json, sys
manifests = json.load(sys.stdin)["manifests"]
actual = {(m["platform"]["os"], m["platform"]["architecture"], m["digest"]) for m in manifests}
expected = {("linux", "amd64", sys.argv[1]), ("linux", "arm64", sys.argv[2])}
if len(manifests) != len(expected) or actual != expected:
    raise SystemExit("the staged index does not bind the checked platform images")' "$amd64" "$arm64"
        if published=$(digest "$final" 2>/dev/null); then
            if [ "$published" != "$staged" ]; then
                echo "Release tag $final already names another digest. Recover using its original release run." >&2
                exit 1
            fi
        else
            docker buildx imagetools create --tag "$final" "$repository@$staged" >&2
        fi
        [ "$(digest "$final")" = "$staged" ]
        printf '%s\n' "$staged"
        ;;
    *)
        echo 'usage: release-oci.sh {restore|stage} IMAGE STAGING_TAG REVISION SOURCE_URL | promote REPO RELEASE RUN' >&2
        exit 2
        ;;
esac
