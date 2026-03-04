#!/bin/bash

if [ $# -eq 0 ]; then
    echo "用法: $0 [curl 参数] <URL>"
    echo "示例: $0 -H 'User-Agent: Mozilla/5.0' https://example.com"
    exit 1
fi

DOMAIN=$(echo "d2VhdGhlci5jb20uY24=" | base64 -d)
TIME="$(date +%s)000"
args=()
for arg in "$@"; do
    arg=${arg/_DOMAIN_/$DOMAIN}
    arg=${arg/_TIME_/$TIME}
    args+=("$arg")
done
set -- "${args[@]}"

curl -s \
-H "Referer: https://m.$DOMAIN/" \
-H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) (KHTML, like Gecko) Chrome/145.0" \
"$@"
