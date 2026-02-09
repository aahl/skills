#!/bin/bash

TOKEN=${1:-BTC}

PAYLOAD=$(jq -n \
  --arg token "$TOKEN" \
  --arg symbol "${TOKEN}USDT" \
  --arg stamp $(date +%s)000 \
'{
  lang: "zh-CN",
  token: $token,
  symbol: $symbol,
  product: "web-spot",
  timestamp: $stamp,
  quoteToken: "",
  version: "v4",
  translateToken: null
}')

JSON=$(curl -s 'https://www.binance.com/bapi/bigdata/v3/friendly/bigdata/search/ai-report/report' \
  -H 'Content-Type: application/json' \
  -H "Referer: https://www.binance.com/zh-CN/trade/${TOKEN}_USDT?type=spot" \
  -H 'User-Agent: Mozilla/5.5.0 AppleWebKit/537 Chrome/143 Safari/537' \
  -H 'lang: zh-CN' \
  --compressed \
  --data "$PAYLOAD")

echo "$JSON" | jq -r '.. | objects | select(has("content") or has("overview")) | .content // .overview | select(. != null)'
