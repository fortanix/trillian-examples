#!/bin/bash -ex

#
# Some basic tests of the trillian serverless tooling.
#
# I think these aren't covered by the existing tests in their source repository.
#
set -o pipefail

if [ -z "$API_KEY" ] ; then
    echo "Set the environment variable API_KEY to the API key to use for testing"
    exit 1
fi

if [ -z "$KEY_ID" ]; then
    echo "Set the environment variable KEY_ID to the key to use for testing"
    exit 1
fi

repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

if [ -z "$SERVERLESS_DIR" ] ; then
    SERVERLESS_DIR="$repo_root/serverless/cmd"
fi

set -u

function usage {
    echo "Usage: serverless-test.sh [--keep-temp-dir]"
    exit 1
}

keep_temp_dir=0

while [ "$#" -gt 0 ] ; do
    arg=$1
    if [ "$arg" = "--keep-temp-dir" ] ; then
        keep_temp_dir=1
        shift
        continue
    fi
    usage
done

set -x

#
# serverless command paths
#
client="$SERVERLESS_DIR/client/client"
generate_keys="$SERVERLESS_DIR/generate_keys/generate_keys"
integrate="$SERVERLESS_DIR/integrate/integrate"
sequence="$SERVERLESS_DIR/sequence/sequence"

tmpdir=`mktemp -d transparency.XXXXXXXX --tmpdir=`
pushd "$tmpdir"

storage_dir="--storage_dir=$tmpdir/log"
keyname="--key_name=log-test-key"
origin="--origin=mylog"

function cleanup {
    popd
    if [ "$keep_temp_dir" = "0" ]; then
        rm -r "$tmpdir"
    fi
}

trap cleanup EXIT

# For the DSM test, we don't need to generate keys, as they're stored in DSM.
#"$generate_keys" "$keyname" --out_pub=public --out_priv=private

"$integrate" --initialise --logtostderr "$storage_dir" --public_key_out=public --dsm_key_id=$KEY_ID --dsm_api_key=$API_KEY "$origin"

public_material=$(cat public)

mkdir entries

for i in {1..64} ; do
    echo "This is entry $i" > "entries/$i"
done

# Sequence the entries. Use two different methods for passing the keys (command line and
# environment variable)
for i in {1..32} ; do
    "$sequence" "$storage_dir" --public_key=public --entries "entries/$i" --logtostderr "$origin"
    "$integrate" "$storage_dir" --public_key=public --dsm_key_id=$KEY_ID --dsm_api_key=$API_KEY --logtostderr "$origin"
done

for i in {33..64} ; do
    SERVERLESS_LOG_PUBLIC_KEY="$public_material" "$sequence" "$storage_dir" --entries "entries/$i" --logtostderr "$origin"
    "$integrate" "$storage_dir" --dsm_key_id=$KEY_ID --dsm_api_key=$API_KEY --logtostderr "$origin"
done

# Client inclusion test.

# TODO: Test JSON output format when that code merges.
# TODO: Test lookup by merkle hash instead of entry contents.

for i in {1..32} ; do
    "$client" --log_public_key=public --logtostderr --log_url=file://"$tmpdir"/log --cache_dir="" "$origin" --output_inclusion_proof=proof.$i inclusion "entries/$i"
done

# Temporarily disabling since we're testing on the tree without this option
for i in {33..64} ; do
    SERVERLESS_LOG_PUBLIC_KEY="$public_material" "$client" --logtostderr --log_url=file://"$tmpdir"/log --cache_dir="" "$origin" --output_inclusion_proof_json=proof.$i.json inclusion "entries/$i"
done


echo "Test passed"
