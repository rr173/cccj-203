# 主数据放行包（master release）格式与语义

`sg master-release` 把**一份 JSON 质量合同**套在现有主数据仓的**当前已提交
头修订**上，产出一个自包含 SQLite 包：可装载区（`load_*`）只含通过准入的行，
拒收账（`reject_*` + 波次账）逐行说明未发的成员映射、归并关系、来源贡献以及
最终去向原因。

它不改裁定、不写主仓、不产生主数据修订，也不是两次修订的差异分析；它只读
消费仓内同一个提交视图，不打开原始情报仓。

## 1. 输入

| 输入 | 说明 |
| --- | --- |
| 主数据仓 | `master-build` 建好的仓。放行在**一个读事务**内取头修订视图：`package_meta`、`revisions` 的头号，以及 `entity_map` / `relations` / `contributions` 三张逻辑表。**不读裁定表 `verdicts`**，也不看 `base_objects` / `base_edges` / `changes`。 |
| 合同 | 见第 2 节；`--contract` 必须是 JSON 文件。 |
| 输出路径 | 先写同目录 `.sqlite.tmp`，整包校验后 `os.replace` 原子发布。 |

并发写入时读事务只看到某一个**已提交**修订，包内不会混入新旧修订的行；
合同摘要、读到的修订号、上游投影标识写在 `package_meta` 里，便于复核。

## 2. 合同（`stix-gate-master-release-contract/1`）

```json
{
  "schema": "stix-gate-master-release-contract/1",
  "relationship_types": ["indicates", "communicates-with", "uses"],
  "exclude_entity_ids": ["indicator--RETIRED"],
  "requirement_groups": [
    {
      "id": "G-IND-OUT",
      "alternatives": [
        {
          "id": "A-IND-OUT",
          "direction": "out",
          "relationship_types": ["indicates"],
          "peer_types": ["indicator"],
          "min_distinct_peers": 1
        }
      ]
    },
    {
      "id": "G-MAL-REACH",
      "alternatives": [
        {
          "id": "A-MAL-CW",
          "direction": "out",
          "relationship_types": ["communicates-with"],
          "peer_types": ["indicator", "malware"],
          "min_distinct_peers": 2
        },
        {
          "id": "A-MAL-IN",
          "direction": "in",
          "relationship_types": ["indicates", "uses"],
          "peer_types": ["malware"],
          "min_distinct_peers": 1
        }
      ]
    }
  ],
  "named_requirement_sets": [
    {"id": "SET-IND", "entity_type": "indicator", "groups": ["G-IND-OUT"]},
    {"id": "SET-MAL", "entity_type": "malware", "groups": ["G-MAL-REACH"]}
  ]
}
```

字段含义：

| 字段 | 必填 | 含义 |
| --- | --- | --- |
| `relationship_types` | 是 | 允许发出的关系类型（至少一项）。声明但本仓从未出现的类型合法。 |
| `exclude_entity_ids` | 是 | 明确排除的主实体 ID；必须是本仓出现过的规范化主键。 |
| `requirement_groups[].id` | 是 | 稳定引用的组 ID。 |
| `requirement_groups[].alternatives` | 是 | 至少一项；满足其中任一项即该组通过。 |
| `alternatives[].id` | 是 | 稳定引用的备选 ID，组内唯一。 |
| `alternatives[].direction` | 是 | `out` 或 `in`，相对被判定实体的方向。 |
| `alternatives[].relationship_types` | 是 | 可计入该备选的关系类型集合（非空）。 |
| `alternatives[].peer_types` | 是 | 可计入的对端实体类型集合（非空）。 |
| `alternatives[].min_distinct_peers` | 是 | 最少**不同对端主实体**数，正整数（布尔/0/负数均拒绝）。 |
| `named_requirement_sets[].id` | 是 | 命名组集合 ID。 |
| `named_requirement_sets[].entity_type` | 是 | 该集合适用的实体类型；每种实体类型至多一个集合。 |
| `named_requirement_sets[].groups` | 是 | 引用 `requirement_groups` 的 ID（非空、不重复、必须存在）。 |

语义要点：

- 一个实体要满足其类型的**全部**必需组；每组由若干备选组成，满足**任一**
  备选即可。备选之间不叠加计数：`A-MAL-CW` 要求 2 个不同对端时，另一个
  备选里的关系不会帮它凑数。
- 从**归并后的关系行**认方向（`source_canon → target_canon`）；对端按主实体
  ID 去重。同一对端点之间不同类型的关系、或同一关系的多条来源贡献，只算一个
  对端。
- 自环不提供支撑；但若其关系类型被允许且端点最终留在包里，自环照发
  （`load_relations.is_self_loop = 1`）。
- **没有登记必需组的实体类型不受数量条件限制**（例如样例里未登记的
  `campaign`、`tool` 之类照样按关系类型过滤后发出）。
- 误配置一律报错，绝不退化成空交付：未知组/集合 ID、空备选列表、未知排除
  主键、非法方向、非正整数阈值、重复 ID、缺字段、类型不符、合同 JSON 损坏，
  分别返回 `invalid-contract` 或 `invalid-contract-json`，并且不产出包。

## 3. 波次语义

- **第 0 波**：去掉合同明确排除的实体及所有与其相连的关系；再去掉关系类型
  不被允许的关系。被排除实体的成员映射记 `excluded-by-contract`，关系记
  `endpoint-excluded`；类型不被允许的关系记 `relationship-type-not-allowed`。
  既碰排除端点又是不允许类型的关系，按“排除优先”只记一个原因。
- **第 1 波及以后**：对**同一份波前存活集**判断。当波所有不满足条件的实体
  **一起**出局；只有下一波才把这次出局算进别人的支撑缺口。因此“互相支撑的
  闭环”可以整体留下，不需要人工选定的根。
- 每条关系随**第一个**出局端点出局，记录那一波；若两端在同一波出局，两个
  端点都会写进 `reject_relations.evicted_endpoints_json`。
- 直到某一波没有实体出局即稳定；剩下的全部实体与关系进入可装载区。
- 对每个自动淘汰的实体，记首次出局波、该波**未满足的全部必需组**、以及这些
  组内**每个备选项**在波前实测的不同对端数与阈值（`eviction_alt_snapshot`，
  `met=0`）。数字在判定该波时落盘，绝不用最终空图回填早期理由。

## 4. 包结构（`stix-gate-master-release/1`）

### 4.1 元信息
| 键 | 含义 |
| --- | --- |
| `release_schema` | `stix-gate-master-release/1` |
| `contract_schema` / `contract_sha256` / `contract_json` | 合同模式、摘要（规范化 JSON 的 SHA-256）与全文 |
| `master_revision` / `master_warehouse` | 包所读的主仓修订号与路径 |
| `upstream_*` | 上游投影标识：`codename`、`t_raw`、`t_key`、`principal`、`policy_digest`、`package_digest_sha256` 等（来自主仓建仓时的包摘要与上下文） |
| `release_digest` | 本轮放行逻辑表、波次账与逐行理由的内容摘要；同视图同合同复跑一致 |
| `wave_count` | 最后一个真正出局的波号（稳定波不计入） |
| `published_at` | 落盘时间（不参与 `release_digest`） |

### 4.2 可装载区
| 表 | 行键 | 列 |
| --- | --- | --- |
| `load_entities` | `obj_id` | 主实体的**全部**成员映射，`obj_id, obj_type, canonical_id` |
| `load_relations` | `row_key` | `row_key, source_canon, relationship_type, target_canon, contribution_count, is_self_loop` |
| `load_contributions` | `relationship_id` | `relationship_id, source_id, target_id, relationship_type, source_canon, target_canon, row_key, is_self_loop, modified_key, modified_raw` |

不放任何裁定表。可装载区保证：每条关系两端都是已装载实体；每条贡献指向一条
已装载关系；`contribution_count` 等于该关系装载的贡献行数。

### 4.3 拒收账
| 表 | 行键 | 说明 |
| --- | --- | --- |
| `reject_entity_map` | `obj_id` | 原键覆盖未发的成员映射；`master_entity_id` 给出所属主实体，`eviction_wave` + `reason` 给出最终去向 |
| `reject_relations` | `row_key` | 未发关系；`eviction_wave`、`reason`（`endpoint-excluded` / `relationship-type-not-allowed` / `endpoint-evicted`）、`evicted_endpoints_json`（该波同时出局的全部端点） |
| `reject_contributions` | `relationship_id` | 未发来源贡献；沿其关系的波次与原因，可按 `row_key` 回查关系 |
| `release_waves` | `wave` | 每波：出局实体/关系/成员映射/贡献数、`candidate_entities`、`probed_counter_rows`、`lost_support_pairs`，以及该波的 `access_json` 访问计数 |
| `support` / `support_count` | `(entity_id, alt_id, peer_id)` / `(entity_id, alt_id)` | 支撑事实账：每个备选、每个实体、每个不同对端一行；计数行在每波按主键递减。它们保持可复算，但**不是**装载接口的一部分 |
| `wave_entity_evictions` | `entity_id` | 每个自动淘汰实体的首次出局波与原因 |
| `eviction_alt_snapshot` | `(entity_id, wave, group_id, alt_id)` | 该波未满足组内每个备选项的实测数与阈值 |

不含任何来源行正文；三类输入行在 `load_*` 与 `reject_*` 之间不重不漏。

## 5. 装载示例

```bash
# 1) 生成（原子发布，失败不覆盖已有包）
python3 -I sg-cli.py master-release \
  --master runtime/master_carol.sqlite \
  --contract tests/data/release_contract.example.json \
  --output runtime/release_carol.sqlite

# 2) 收据（含每波计数与访问量证据）
python3 -I sg-cli.py master-release-read \
  --package runtime/release_carol.sqlite --what manifest

# 3) 查某个未发主实体：所属主实体、出局波、各备选实测数与受影响关系
python3 -I sg-cli.py master-release-read \
  --package runtime/release_carol.sqlite --what entity --entity malware--M1

# 4) 单独看“合同禁发类型”造成的拒收
python3 -I sg-cli.py master-release-read \
  --package runtime/release_carol.sqlite --what table --table reject_relations

# 5) 下游直接装载（只读打开）
sqlite3 -readonly runtime/release_carol.sqlite \
  "SELECT obj_id, canonical_id FROM load_entities ORDER BY obj_id;"
```

装载次序：`load_entities` → `load_relations` → `load_contributions`
（或先装实体再按 `row_key` 装关系与贡献）；跳过 `load_*` 以外的表，或只读
`reject_*` 作为不入库的对账。包可直接复制重开，`PRAGMA integrity_check`
可独立复核。

## 6. 可独立复算的小夹具

`tests/release_fixtures.py` 生成两个自包含的人造投影包，`master-build`
绑定后用示例合同放行即可复算（全部为虚构 ID，不含真实情报）：

**夹具 A（`--scenario main`）**

```
I1 → I2 → I3 → I4            （链）
I5 ⇄ I6                      （互指环）
I7 ⟲ I7, I7 → I5             （自环 + 出边）
M1 → I2 (communicates-with), M1 → I2 (uses), M1 ⟲ M1
M2 → I7 (communicates-with), M2 → I5 (uses)
```

合同：`indicator` 需至少 1 个出向 `indicator` 对端；`malware` 需至少 2 个不同
出向对端（`communicates-with` 或 `uses` 各自可满足，对端可为 `indicator` 或
`malware`）。预期：

| 实体 | 出局波 | 说明 |
| --- | --- | --- |
| `I4` | 1 | 链尾无出向对端，实测 0 / 阈值 1 |
| `M1` | 1 | 两种类型都指向同一个 `I2`，按对端去重后实测 **1** / 阈值 2；自环不计 |
| `M2` | 1 | 两个类型各指向一个不同对端，但每个备选只要求同类型计数，实测 1 / 阈值 2 |
| `I3` | 2 | `I4` 出局后失去唯一出向对端 |
| `I2` | 3 | `I3` 出局后失去唯一出向对端 |
| `I1` | 4 | `I2` 出局后失去唯一出向对端 |

可装载区：`I5, I6, I7` 三实体、`I5→I6`、`I6→I5`、`I7→I5` 与自环 `I7→I7`。
`I1→I2` 在第 3 波随 `I2` 出局，`I2→I3` 在第 2 波、`I3→I4` 在第 1 波；
`M1` 的三条关系都在第 1 波出局，`evicted_endpoints_json` 为 `["malware--M1"]`。

**夹具 B（`--scenario inbound`）**：只有入向边，验证 `direction: "in"` 与
“同一波两端一起出局”；**夹具 C（`--scenario same_wave`）** 两个 Malware 只互相
指向且各要求 2 个对端，二者第 1 波同日淘汰、两条关系都记
`evicted_endpoints_json = ["malware--Q1","malware--Q2"]`；**夹具 D
（`--scenario excluded`）** 覆盖明确排除与自环；**夹具 E（`--scenario empty`）**
给出合法空装载结果。

复算：

```bash
python3 -I tests/release_fixtures.py /tmp/pkg.sqlite --scenario main
python3 -I sg-cli.py master-build --package /tmp/pkg.sqlite --master /tmp/m.sqlite
python3 -I sg-cli.py master-release --master /tmp/m.sqlite \
  --contract tests/data/release_contract.example.json --output /tmp/r.sqlite
python3 -I sg-cli.py master-release-read --package /tmp/r.sqlite --what waves
```

## 7. 访问量与规模

- 建账（第 0 波）一次性物化支撑事实（`support` / `support_count`），之后每波
  只做两类工作：按主键读候选实体的计数值、按 `support(peer_id)` 索引扣减
  “刚失去的对端”。**不会按波扫描无关分区**，也不会为一个失去的对端重扫整条
  高扇出邻接表——高扇出的一端出局时，其失去的支撑对在该波按批量处理并从此
  不再访问。
- 每波的 `release_waves` 行给出可复跑的访问量证据：
  - `candidate_entities`：该波实际判定的实体数（稳定后应回落到 1–2）；
  - `probed_counter_rows`：该波实际读到的 `support_count` 行数；
  - `lost_support_pairs`：该波扣减的支撑对数；
  - `access_json`：按阶段/表/种类的 filtered/scan/write 计数。
- `tests/run_release_verify.py` 用长淘汰链旁挂大规模无关稳定分区与高扇出
  样例断言：初始建账后每波候选数与 `support_count` 探测数始终为常数、每波
  执行相同的少量语句、没有全表扫描，且内存不随语料线性增长。样例数据在
  运行时合成于临时目录，不随仓库提交。

## 8. 错误码

| 码 | 含义 |
| --- | --- |
| `invalid-contract` | 合同结构/语义错误（未知组或集合引用、空备选、未知排除主键、非法方向、非正整数阈值、重复 ID 等） |
| `invalid-contract-json` | 合同文件不是合法 JSON/UTF-8 |
| `invalid-release-input` | 主仓头视图与建仓底稿不一致，或某主实体跨多种实体类型 |
| `master-missing` | 主仓不存在或无已提交修订 |
| `integrity-failure` | 生成的包未通过 SQLite 完整性检查 |
| `internal-invariant` | 两区不满足不重不漏/两端齐全等自检（正常不应出现，出现即不发布） |
| `storage-error` | SQLite 层失败（不泄漏正文或路径细节） |

失败时临时文件被删除、目标路径上的旧包保持原字节不变：不会留下可被误装载的
半成品。
