# 实体主数据仓（master warehouse）格式说明

主数据仓是一个独立的 SQLite 文件，由 `sg-cli.py master-build` 从**一个**
`sg export` 产生的投影包建立，建仓完成即为修订 0，之后永不换包、不跨分析员
拼包。所有写入在单个 SQLite 事务内提交，读四表始终看到同一个修订号。

## 1. 表结构（schema `stix-gate-master/1`）

### 1.1 不可变底稿
| 表 | 主键 / 索引 | 内容 |
| --- | --- | --- |
| `package_meta` | `key` | 投影包摘要（`package_digest_sha256`、字节数）与上下文（codename、时点、principal、policy 摘要、schema），建仓时一次性登记 |
| `base_objects` | `obj_id` | 实体基表。只收录投影 `objects` 中 `indicator` / `malware` 行，保留 `obj_id, obj_type, modified_key, modified_raw` 版本坐标 |
| `base_edges` | `relationship_id`，两端各有索引 | 关系底稿。仅当边的两端都在实体基表、对应 Relationship 投影正文的 `source_ref/target_ref` 与边一致、且正文有非空字符串 `relationship_type` 时收录；被拒边只计数不补值 |

### 1.2 裁定账本
| 表 | 内容 |
| --- | --- |
| `adjudications` | 每条裁定一行：`verdict_id`、`kind`（same/different）、规范化（UTF-8 字节序）端点对、`priority`（仅 same）、`status`（active/retracted）、最后更新批号与修订号。端点无方向，落库前统一按字节序排列 |
| `batch_receipts` | 批号、输入字节的 SHA-256 与长度、预期父号、收到时父号、发布修订号、操作数、变更数。重送同批号同字节据此幂等返回原修订 |
| `revisions` | 修订链：修订号、父修订号、批号、时间戳、变更数、备注（build/batch）。空差值也有修订头 |

### 1.3 四张逻辑表（始终等于当前头修订）
| 逻辑表名 | 物理表 | 稳定行键 | 列 |
| --- | --- | --- | --- |
| `entity_map` | `t1_entity_map` | `obj_id` | `obj_id, obj_type, canonical_id`（主键 = 组内 UTF-8 字节最小对象 ID，不是树根） |
| `relations` | `t2_relations` | `row_key` = JSON `[源主键, 关系类型, 目标主键]` | `source_canon, relationship_type, target_canon, contribution_count, is_self_loop` |
| `contributions` | `t3_contributions` | `relationship_id` | 原关系 ID、原两端 ID、关系类型、归并后两端主键、`row_key`、`is_self_loop`、原版坐标 `modified_key/modified_raw` |
| `verdicts` | `t4_verdicts` | `verdict_id` | `kind`、规范化端点对、`priority`、`result`（same: `merged/already-same/blocked`；different: `constraint`）、`blocking_verdict_id`（阻挡时为当时跨两组的最小 different 裁定 ID） |

约定：双向关系是两行；不同 `relationship_type` 不合并；两端归到同组时保留
一条 `is_self_loop=1` 的自环，其贡献明细同样保留。

### 1.4 变更流
`changes` 表保存每个修订相对其父修订的**行级差值**：
`revision, parent_revision, table_name, row_key, op(delete|replace), row_json`。
顺序固定为逻辑表顺序（entity_map → relations → contributions → verdicts）
再按行键。未变化的行不重发；删除只有键没有行体，替换携带整行。不需要保存
任何旧修订的完整副本——旧状态可由修订 0 全量读取加逐修订变更重放得到。

## 2. 分组与裁定结果语义

1. 每个实体初始自成一组；所有有效 `different` 始终是不可同组约束。
2. `same` 按优先级降序、同级按裁定 ID 的 UTF-8 字节升序处理。
3. 两端已同组 → `already-same`；两组间存在任何禁止合并的端点对 → `blocked`
   并记录跨这两组的最小 `different` 裁定 ID；否则合并 → `merged`。
4. 同批操作先在内存/账本形成完整的新有效裁定集合，再统一算主数据，绝不按
   文件内操作顺序逐条发布。
5. 撤回、替换或调优先级后允许旧组拆分、旧阻挡转为通过；即使终态成员映射
   没变，裁定结果或阻挡证据变化也会产生替换行。

## 3. 增量重算的访问范围

后续批次**不重新打开投影包、不全量重算分组、不全表扫描四张结果表**：

1. 收集本批所有 `put`/`retract` 触及的新旧端点作为种子；
2. 经有效 `same` 候选（含被 `blocked` 的候选）双向 BFS 得到封闭区域，
   BFS 只走 `adjudications(endpoint_a/endpoint_b)` 上的索引；
3. 仅在该区域内重跑分组算法并重算 T1/T4；
4. 关系只访问 `base_edges` 中端点落在区域内的边，以及这些边当前/新归属的
   归并键下的贡献，不触碰无关分区；
5. 差值由区域内行的修订前后对比产生。

可核查证据有两类，均不依赖运行时间或写入行数：

- **分阶段访问计数**：所有连接使用 `InstrumentedConnection`，按阶段统计表的
  `filtered`（带 WHERE 的索引访问）/ `scan`（无 WHERE 的 SELECT 全扫）/
  `write`。`master-apply` 收据中的 `access` 字段直接给出计数；建仓后批次对
  八张数据表的 `scan` 必须恒为 0（仅 `revisions` 这种账本小表允许
  `MAX(revision)` 扫描）。
- **查询计划**：`EXPLAIN QUERY PLAN` 显示区域 BFS 等查询为 `SEARCH ... USING
  INDEX`，不出现 `SCAN adjudications`。

`tests/run_master_verify.py` 在 0 / 100 / 1000 / 4000 个无关分区下断言纠错
批次的过滤访问计数完全相同，证明访问范围与无关数据量无关。

## 3a. 主数据修订影响分析（只读，不改动仓内任何裁定/修订/变更）

`sg impact`（CLI `master-impact-summary` / `master-impact-page`）针对同一仓内
两个**已提交**修订 `s <= e` 生成确定性影响报告。它不假设仓保存任意旧修订的
完整快照：报告的全部状态只由两条可独立复现的路径构造——

1. 从不可变底稿 `base_objects` / `base_edges` 按建仓规则重建修订 0 四表
   （每个实体自成一组；每条底稿边按原始端点与关系类型形成贡献键）；
2. 沿 `changes` 变更流逐修订正向重放（delete/replace、主键迁移、端点贡献
   关联均按行严格应用）。

重放至头修订的结果必须等于物理头表，`run_impact_verify.py` 对此逐表断言。
影响分析只访问 `base_objects`、`base_edges`、`changes`、`revisions`、
`package_meta` 五张表，且对它们零全表扫描（访问计数可核查）。

### 输入绑定与拒绝规则

- 输入绑定仓身份（`warehouse_instance_id` + 包摘要 + 报告版本）与起止修订号；
- 未知仓 → `master-missing`；未知修订 → `unknown-revision`；反向区间
  （`s > e`）→ `reversed-range`；不存在“未提交状态”输入，因为修订号只能来自
  已提交链，引用未提交号一律按未知修订拒绝；
- `s == e` 返回合法的零影响报告：无转移明细，累计净变化与搅动均为 0；
- 报告从不声称某条裁定“导致”变化，输出中不出现任何裁定 ID，只陈述相邻已提交
  修订之间可观察到的关联事实。

### 每个转移（相邻修订对）报告内容

- 对象映射变化：`included` / `exited` / `primary_changed`，逐条给出对象 ID 与
  前后主实体（canonical id）；底稿不可变，正常运行只出现主实体改变；
- 实体组数量：前后计数与 delta；
- 关系键变化：`appeared` / `disappeared` / `modified`（贡献数、自环标记）与
  `migrations`；
- 关系贡献数量：逐键 before/after/delta 与区间总贡献数（底稿边不可变，总量守恒）；
- 关系自环变化：逐条 old/new 键与前后自环标记。

### 关系键迁移的识别（不按旧键删除+新键新增掩盖）

以**原始贡献关系 ID、原始两端点与关系类型**为稳定身份，在旧键与新键之间构造
二部图（同键保留的贡献同时登记在两侧，使“保留+迁出”的键保持连通），连通分量
分类为：

- `migrated`：1 旧键 ↔ 1 新键；
- `split`：1 旧键 → 多新键（一对多，分量内逐边列出保留与迁出的贡献 ID，
  不猜测唯一对应）；
- `merge`：多旧键 → 1 新键（多对一）；
- `complex_remap`：多对多重映射。

每个分量的 `edges` 给出 old/new 键、贡献数与贡献关系 ID；JSONL 的
`migration_contribution` 行进一步给出该贡献的原始端点、关系类型与前后归并坐标
（含 `modified_key/modified_raw` 原版坐标），可分页回查。

### 净变化 vs. 期间发生过变化

累计结果**只由两个边界状态的差异**计算；逐转移绝对变化量之和单独记为
`transition_absolute_churn`，绝不冒充净变化。区间内改变后又恢复的对象/关系：

- 累计净变化为 0，但出现在 `touched` / `reverted`（边界相同）或 `transient`
  （仅区间内存在）中，并带 `touched_revisions` 指向可定位的逐转移明细。

### 报告形态与分页

- `master-impact-summary`：一份完整 JSON（仓身份、区间、逐转移明细、累计块）；
- `master-impact-page`：按全局稳定排序键分页的 JSONL 明细（每修订一个连续键
  块，累计块固定在后），末行为页信封；支持 `--scope`（all/transitions/
  cumulative）、`--filter-kind`（object/relation/migration/contribution）与
  `--revision` 过滤；
- 分页令牌为 HMAC 签名，绑定仓实例、起止修订、过滤条件、页大小与报告版本；
  篡改、跨查询或跨仓复用均被拒绝（`invalid-page-token` /
  `page-context-mismatch`），重复读取同一页结果一致；
- 明细由生成器流式产出，逐转移记录产出即释放（核验用弱引用证明不常驻），
  进程内存不随全量明细线性增长。

## 4. 并发与崩溃

- 每个批次以 `BEGIN IMMEDIATE` 打开写事务：两个写者用同一父号提交不同批次，
  最多一个提交，另一个得到 `stale-parent-revision`。
- 同批号同字节重送：不重新应用，返回原修订（`deduplicated: true`），即使头
  修订已经前移也不误拒；同批号不同字节 → `batch-id-conflict`。
- 所有裁定、映射、关系与贡献、变更记录、批次收据在同一事务提交；进程中断后
  SQLite 回滚，重开只见完整旧状态或完整新状态。测试用 `SG_MASTER_FAULT=1`
  在 COMMIT 前注入故障验证。

## 5. 错误码约定（内容无关）

- `batch-rejected`：批次结构/语义错误的统一通用错误（未知端点、跨类型、
  端点相同、缺优先级、重复裁定 ID、未知撤回等），错误正文不回显端点，也不
  区分端点为何缺失；
- `stale-parent-revision`：预期父号不是当前头；
- `batch-id-conflict`：同批号不同字节；
- `invalid-package` / `integrity-failure` / `master-exists` /
  `master-missing` / `unknown-revision` / `unknown-table` / `storage-error`；
- 影响分析专用：`reversed-range`（起止修订反向）、`invalid-page-token`
  （分页令牌签名无效或损坏）、`page-context-mismatch`（令牌绑定的仓、区间、
  过滤条件或页大小与当前查询不符）、`invalid-filter`（非法过滤参数）。

## 6. 合成数据声明

`tests/master_fixtures.py`、`tests/impact_fixtures.py`、
`tests/run_master_verify.py` 与 `tests/run_impact_verify.py` 使用的全部是
人造 ID（`indicator--A`、`relationship--R1` 等）与合成投影包，不含真实情报
数据。大规模数据库在测试运行时生成于临时目录（规模由 `SG_MASTER_SCALE` /
`SG_IMPACT_SCALE` 控制），核验结束即删除，不随仓库提交。
