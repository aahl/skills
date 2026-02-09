#!/bin/bash

PAGE=${1:-1}
SIZE=${2:-20}
TYPE=${3:-push}

curl -s "https://api.theblockbeats.news/v1/open-api/open-flash?size=$SIZE&page=$PAGE&type=$TYPE" \
  -H 'Accept: application/json' \
  -H 'Referer: https://m.theblockbeats.info' \
  -H 'User-Agent: Mozilla/5.5.0 AppleWebKit/537 Chrome/143 Safari/537' \
  --compressed \
  --data "$PAYLOAD" | jq -r '.data.data[].content'
