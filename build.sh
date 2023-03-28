#!/bin/bash -ex

set -o pipefail

repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}"))

cd "$repo_root"

# Try to find the toolchain directory automatically if it's not specified.
if [ -z "$TOOLCHAIN_DIR" ] ; then
    if ! [ -d "$repo_root"/../toolchain ] ; then
        echo "Unable to find toolchain in $repo_root/toolchain."
        echo "You may need to check out toolchain or set TOOLCHAIN_DIR to the toolchain location"
        exit 1
    fi
    TOOLCHAIN_DIR="$repo_root/../toolchain"
fi

source "$TOOLCHAIN_DIR/shell/malbork_env"

cd "$repo_root/serverless/cmd"

for i in approve client generate_keys integrate sequence ; do
    pushd $i
    rm -f $i
    go build .
    popd
done
