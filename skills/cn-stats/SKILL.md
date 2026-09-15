---
name: cn-stats
description: 中国国家统计局公开数据查询技能，当用户想查询经济、CPI、GDP、人口、房价指数等数据时触发。
---

# 国家统计局
```bash
# 全局环境变量
BASE_URL='https://data.stats.gov.cn/dg/website/publicrelease/web/external'

JQ_INDICATORS='.data | {total}, (.list[] | {_id, type, chart_style_text, i_showname})'
JQ_AREAS='.data[] | [.name_value,.name_text] | @tsv'

# 获取指标分类根节点ID
# code: {1:月度数据, 2:季度数据, 3:年度数据， 4:分省月度数据, 5:分省季度数据, 6:分省年度数据}
#       {7:主要城市月度价格, 8:主要城市年度数据, 9:港澳台月度数据, 10:港澳台年度数据}
#       {12:三大经济体月度数据, 13:国际市场月度商品价格, 14:主要国家年度数据}
ROOT_ID=$(curl "$BASE_URL/new/queryIndexTreeAsync?pid=&code=1" | jq -r '.data[0]._id // .')

# 获取指标分类子节点
curl "$BASE_URL/new/queryIndexTreeAsync?pid=$ROOT_ID&code=1" | jq -r '.data[] | {_id, name, type, isLeaf}'

# 获取指标列表 (isLeaf==true)
curl "$BASE_URL/new/queryIndicatorsByCid?cid=$NODE_ID&dt=&name=" | jq -r $JQ_INDICATORS

# 搜索指标列表
curl -G "$BASE_URL/new/queryIndicatorsByCid?cid=&dt=&rootId=$ROOT_ID" \
  --data-urlencode 'name=<关键词>' \
| jq -r $JQ_INDICATORS

# 获取统计数据 - 多指标
# dts: 时间范围 {年: 2026YY | 2022YY-2026YY, 月: 202501MM-202512MM}
curl "$BASE_URL/stream/esData" \
  -H 'Content-Type: application/json;charset=UTF-8' \
  -H 'Referer: https://data.stats.gov.cn/dg/website/page.html' \
  --data-raw '{
  "cid": "分类NODE_ID(isLeaf==true)",
  "indicatorIds": ["指标ID1","指标ID2"],
  "daCatalogId": "",
  "das": [{"text":"全国","value":"000000000000"}],
  "showType": "1",
  "dts": "",
  "rootId": "根节点ROOT_ID"
}' | jq -r '
  .data[] | 
  .name as $year |
  .values[] |
  [$year, ._name, .value // "-", .du_name] |
  @tsv
'

# 获取地区分类
curl "$BASE_URL/getDaCatalogTreeByIndicatorCid?indicatorCid=$NODE_ID"

# 获取地区列表
curl "$BASE_URL/getDasByDaCatalogId?daCid=$DA_CATELOG_ID&rootId=$ROOT_ID" | jq -r $JQ_AREAS

# 获取国内全部省份
curl "$BASE_URL/getDasByDaCatalogId?daCid=a10dceae75d245008bf4b9a0e6fe1d55" | jq -r $JQ_AREAS

# 获取国内大中城市
curl "$BASE_URL/getDasByDaCatalogId?daCid=44016f1bffeb4ea49fe34e100c6415fb" | jq -r $JQ_AREAS

# 获取统计数据 - 多地区
curl "$BASE_URL/stream/esData" \
  -H 'Content-Type: application/json;charset=UTF-8' \
  -H 'Referer: https://data.stats.gov.cn/dg/website/page.html' \
  --data-raw '{
  "cid": "分类NODE_ID(isLeaf==true)",
  "indicatorIds": ["指标ID"],
  "daCatalogId": "",
  "das":[{"text":"上海市","value":"310000000000"},{"text":"北京市","value":"110000000000"}],
  "showType": "3",
  "dts": ["202301MM-202512MM"],
  "rootId": "根节点ROOT_ID"
}' | jq -r '
  .data[] | 
  .name as $year |
  .values[] |
  [$year, ._name, .value // "-", .du_name] |
  @tsv
'

# 全局数据查询
curl -G "$BASE_URL/query?code=&pagenum=1&pageSize=15" \
  --data-urlencode 'search=<中文关键词>' \
  -H 'client: pc' \
  -H 'Accept: application/json, text/plain, */*' \
  -H 'Referer: https://data.stats.gov.cn/dg/website/page.html' \
| jq -r '.data | {types,count}, (.data[] | {cid,indic_id,show_name,da_name,da,dt,dt_type,value,explain})'
```

## 常用数据
```bash
# 大中城市住宅销售价格指数
curl "$BASE_URL/new/queryIndicatorsByCid?cid=3eb43764c74741469b745c396cf002d1&dt=&name=" | jq -r $JQ_INDICATORS
```
