#!/bin/sh
# Strip Rust 4-part --target=... triples so zig cc targets arm-linux-musleabi (ARMv6 soft-float musl)
first=1
for arg in "$@"; do
    if [ "$first" = "1" ]; then
        set --
        first=0
    fi
    case "$arg" in
        --target=*) continue ;;
        *) set -- "$@" "$arg" ;;
    esac
done
exec zig cc -target arm-linux-musleabi -mcpu=mpcorenovfp -mfloat-abi=soft "$@"
