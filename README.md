# STIX Gate — 版本化接入与授权分析投影

把离线 STIX 2.1 bundle 接入受保护源仓，按 (集合代号, 时点 t, principal,
策略摘要) 生成**物理隔离**的分析投影。普通调用者只能查询投影，永远接触不到
受限原值。本系统不做登录后台、不做威胁检测/攻击判定，只产出可按时点复查、
且不把受限字段带入检索的情报关系。

## 1. 目录结构

```
sg/                      产品代码（纯标准库，无第三方依赖）
  util.py                规范 JSON、时间解析、NDJSON 流式读取
  selectors.py           STIX 2.1 granular selector 解析与路径覆盖
  markings.py            policy 加载、标记可见性、字段授权
  redact.py              投影渲染（删属性 / 数组元素 null 占位）
  store.py               受保护源仓：stage/finalize、版本选择、诊断
  projection.py          隔离投影 SQLite、检索索引、分页令牌、引用边
  master.py              实体主数据仓：人工裁定分组、四表、修订变更流、访问计数
  impact.py              主数据修订影响分析：修订0重建+变更重放、迁移分量、流式分页
  release.py             主数据放行包：质量合同准入、波次淘汰账、可装载/拒收两区
  cli.py                 命令行入口
sg-cli.py                启动器（python -I 安全运行）
tests/
  data/                  合成 STIX bundle 与 policy.json（全部人造数据）
  hand_expected/         手写每人每时点预期（不由裁定器生成）
  master_fixtures.py     主数据仓核验用合成投影包生成器（人造数据）
  impact_fixtures.py     影响分析核验用多修订合成仓（合并/撤回拆分/迁移/恢复/规模）
  run_master_verify.py   主数据仓端到端核验（95 项，含并发/崩溃/规模访问范围）
  run_impact_verify.py   修订影响分析核验（124 项，含手写预期/独立重放/流式分页）
  release_fixtures.py    放行核验用合成投影包与合同（人造数据，含长链/高扇出样例）
  run_release_verify.py  放行包核验（141 项，含独立逐波枚举/合同误配/并发/访问范围）
  run_unit_verify.py     selector/redact 单元核验（25 项）
  run_verify.py          端到端核验（75 项）
  run_atomic_verify.py   原子性核验（10 项）
  run_bulk_verify.py     大数据量流式/内存核验（18 项）
  gen_bulk.py            生成大量嵌套数组合成对象
docs/
  master_warehouse.md    主数据仓 SQLite 格式、增量范围与错误码说明
  master_release.md      放行合同与放行包的表结构、波次语义、装载示例
```

## 2. 核心语义（与需求逐条对应）

### 身份与版本
- 逻辑对象身份 = `(type, id)`，版本键 = `modified` 微秒时间。
- `created` 晚于 `modified` 的版本记为 `invalid-time`，不进入任何投影。
- 时点查询选择 `modified <= t` 的最新版本；未来版本在到达其 modified 前不可见。
- 同身份、同 `modified` 但规范内容（RFC8785 风格 canonical JSON）不同 →
  `conflict`，该逻辑对象在受影响时点整体不可用，**不回退旧版掩盖冲突**；
  冲突时点之前的精确历史仍可按旧时点读取；出现更新的一致版本后恢复。
- `revoked=true` 使该版及其后视图不可用；撤销前历史仍按旧时点可读。
- 本 profile **不允许撤销后恢复**：若之后出现 `revoked=false`，判为业务冲突，
  不自行发明“恢复”含义。

### 标记与授权（policy.json）
- policy 仅登记 `principal` 与 `allowed_marking_ids`；不实现 STIX 之外的
  通用策略语言，标记定义正文一律视为不透明标签，不从 TLP/Statement 措辞猜等级。
- 每个标记 id 在集合内必须有唯一 marking-definition；同 id 不同 canonical
  正文 → 定义冲突，所有引用该标记的对象普通投影不可用。
- 对象级：`object_marking_refs` 全部获准才整行可见。
- 字段级：某路径的有效标签 = 对象标签 ∪ 所有覆盖该路径的 granular 标签；
  调用者须全部获准，否则该路径被屏蔽。
- 未知标记、非法 selector、定义冲突 → 所属对象普通投影不可用；管理员可经
  `diagnostics` 查失败位置，普通错误不回显正文。
- 无任何标签的对象/字段公开。

### granular selector 与投影
- 按 STIX 2.1 字段与数组索引语法解析：`labels.[1]`、
  `external_references.[0].source_name`；引用位置必须在**原始版本**存在。
- 父路径限制适用于整个子树；多 selector 重叠不依赖声明顺序（已单测覆盖）。
- 先在原始路径上判定，再形成投影：隐藏对象整行不输出；可见对象中隐藏**属性
  删除**，隐藏**数组元素以 null 占位**保持原索引，并在 `redacted` 中明确列出
  该位置，绝不输出原值；删数组元素后不会重新解释后续 selector。
- `type/id/spec_version/created/modified` 等身份/版本字段若被 granular 隐藏，
  在**接入时**即判该对象普通投影整体不可用，防止经另一入口泄漏。

### 关系（业务引用）
- 仅 Relationship 的 `source_ref/target_ref` 视为本 profile 的业务引用。
- 先选时间视图再解释；只有关系本身与两端对象都可见，才输出该边并计数。
- 隐蔽/缺失端点统一不匹配，不回显其身份、正文或标记；其它 `*_ref(s)` 仅作
  unsupported 来源保留，不假装完整遍历。

### 检索、分页与隔离
- 可对 `pattern / name / description / labels` 做精确值或 UTF-8 子串检索；
  `pattern` 当不透明字符串，不执行 STIX pattern 语言。
- 检索/命中数/排序/分页全部在**授权后的投影索引**上执行；隐藏值与不存在字段
  都不匹配，`null` 不当字符串，隐藏值无法借命中、计数或异常回显泄漏。
- 分页令牌 HMAC 签名并绑定 集合代号、t、principal、policy 摘要、查询条件；
  跨身份复用或策略换版（摘要变化）一律拒绝，绝不偷换一页数据。

### 信任边界
- 受保护源仓 SQLite 持有原始正文；普通可访问的投影/索引/导出包不含任何受限
  原值（删除属性、数组 null 占位、索引只建在投影值上）。
- 投影是**独立 SQLite 文件**，不是在最终 JSON 里临时删字段；导出包可复制重开，
  以只读模式查询。
- 持有源仓数据库文件的人不在本 API 信任边界内；管理员读取原始正文必须显式
  `--reveal`。

### 原子性
- 投影先写 `.tmp` 再 `os.replace` 原子发布；构建失败清理全部产物，不留可被
  当成成功的半投影（见 `run_atomic_verify.py`）。
- bundle 解析中断回滚整个 stage，绝不发布新集合代号。

## 3. 完整接入 / 投影 / 导出 / 重开命令

所有命令用 `python3 -I` 运行（隔离模式：忽略 PYTHONPATH 与当前目录，防止
数据目录里的 `json.py` 之类被当模块导入）。

```bash
cd /workspace

# (1) 接收完整 bundle 集合到一个 stage（支持 .json bundle 与流式 .ndjson）
python3 -I sg-cli.py stage \
  --store runtime/source.sqlite --stage-id s-main \
  tests/data/00_markings.json tests/data/01_main.json \
  tests/data/02_versions.json tests/data/03_failures.json

# (2) 发布不可变集合代号 C1（--policy 用于校验策略引用的标记都存在）
python3 -I sg-cli.py finalize \
  --store runtime/source.sqlite --codename C1 \
  --stage-id s-main --policy tests/data/policy.json

# (3) 列已发布集合
python3 -I sg-cli.py collections --store runtime/source.sqlite

# (4) 为某 principal 在时点 t 构建隔离投影
for p in alice bob carol; do
  python3 -I sg-cli.py project \
    --store runtime/source.sqlite --proj-dir runtime/proj \
    --codename C1 --at 2026-02-01T00:00:00Z \
    --principal $p --policy tests/data/policy.json
done

# (5) 按 id 取投影对象
python3 -I sg-cli.py get --proj-dir runtime/proj --codename C1 \
  --at 2026-02-01T00:00:00Z --principal carol \
  --policy tests/data/policy.json --id indicator--O

# (6) 检索（精确 / 子串；field 可为 pattern|name|description|labels|any）
python3 -I sg-cli.py search --proj-dir runtime/proj --codename C1 \
  --at 2026-02-01T00:00:00Z --principal carol \
  --policy tests/data/policy.json \
  --field labels --match exact --term public-word-T --limit 1

# (7) 引用上下游（隐蔽端点不回显）
python3 -I sg-cli.py references --proj-dir runtime/proj --codename C1 \
  --at 2026-02-01T00:00:00Z --principal carol \
  --policy tests/data/policy.json --id indicator--NEST

# (8) 管理员诊断（默认只有失败位置，无正文）
python3 -I sg-cli.py diagnostics --store runtime/source.sqlite --codename C1
# 显式 reveal 才能在诊断里带正文
python3 -I sg-cli.py diagnostics --store runtime/source.sqlite \
  --codename C1 --reveal
# 直接读受保护源仓原始正文，必须显式 --reveal
python3 -I sg-cli.py source --store runtime/source.sqlite \
  --codename C1 --id indicator--BADSEL --reveal

# (9) 导出独立 SQLite 包（完整性校验 + 原子落盘）
PROJ=$(ls runtime/proj/proj_C1__*carol__*.sqlite | head -1)
python3 -I sg-cli.py export --projection "$PROJ" \
  --output runtime/exported_carol.sqlite

# (10) 复制后只读重开查询（file:...?mode=ro）
python3 -I sg-cli.py reopen --package runtime/exported_carol.sqlite \
  search --field labels --match exact --term public-word-T
```

## 3a. 实体主数据仓（人工裁定别名归并）

主数据仓只接受**一个** `export` 投影包，建仓即修订 0，之后不换包、不跨分析员
拼包，也不再需要原始库或策略文件；原有接入/投影/检索命令完全不变。别名只来自
人工裁定批次，系统不猜测、不求最大合并数。格式与增量范围见
[`docs/master_warehouse.md`](docs/master_warehouse.md)。

```bash
# (11) 用一个导出包建立主数据仓（顺序扫包一次，原子落盘）
python3 -I sg-cli.py master-build \
  --package runtime/exported_carol.sqlite \
  --master runtime/master_carol.sqlite

# (12) 应用裁定批次（批号唯一、带预期父修订号；整批先形成新有效集合再发布）
cat > /tmp/batch1.json <<'JSON'
{"batch_id":"B1","expected_parent":0,"operations":[
  {"op":"put","verdict_id":"V-AB","kind":"same",
   "a":"indicator--A","b":"indicator--B","priority":3},
  {"op":"put","verdict_id":"V-AD","kind":"different",
   "a":"indicator--A","b":"indicator--D"},
  {"op":"retract","verdict_id":"V-OLD"}]}
JSON
python3 -I sg-cli.py master-apply \
  --master runtime/master_carol.sqlite --batch /tmp/batch1.json
# 收据含 published_revision、change_count 与分阶段 access 访问计数；
# 同批号同字节重送返回原修订（deduplicated:true），不重新应用。

# (13) 一次一致性读取四张逻辑表与同一个修订号（也可 --table 单表、--jsonl）
python3 -I sg-cli.py master-read --master runtime/master_carol.sqlite
python3 -I sg-cli.py master-read --master runtime/master_carol.sqlite \
  --table verdicts --jsonl

# (14) 按已提交修订读取确定顺序的 JSONL 变更（含父号/新号、表、行键、删除/替换）
python3 -I sg-cli.py master-changes --master runtime/master_carol.sqlite \
  --from 1 --to 2

# (15) 修订链与建仓包摘要/上下文
python3 -I sg-cli.py master-revisions --master runtime/master_carol.sqlite
python3 -I sg-cli.py master-context  --master runtime/master_carol.sqlite
```

### 主数据修订影响分析（只读审计报告）

针对同一仓两个**已提交**修订（`--from s --to e`，允许 `s == e` 的合法零影响
报告）生成确定性影响报告；不修改仓内裁定、修订或变更流，状态仅由修订 0 底稿
加已提交变更重放构造，不读取任何旧修订完整快照。

```bash
# (16) 完整 JSON 摘要：逐转移（对象映射/实体组/关系键/贡献数/自环）+ 区间累计。
#      累计净变化只取两端边界差异；逐转移绝对量之和单列为 churn，绝不冒充净值；
#      关系键拆分/合并按原始端点+关系类型识别为 split/merge/migrated 分量，
#      一对多不猜测唯一对应；改变后恢复的对象/关系标 touched/reverted。
python3 -I sg-cli.py master-impact-summary \
  --master runtime/master_carol.sqlite --from 1 --to 2

# (17) 稳定排序键分页的 JSONL 明细（末行为页信封），令牌 HMAC 绑定仓/区间/
#      过滤/页大小/报告版本，篡改或跨查询复用一律拒绝；可按族与转移过滤。
python3 -I sg-cli.py master-impact-page \
  --master runtime/master_carol.sqlite --from 0 --to 2 --page-size 100 \
  --filter-kind migration
python3 -I sg-cli.py master-impact-page \
  --master runtime/master_carol.sqlite --from 0 --to 2 \
  --scope cumulative --revision 2
```

明细由生成器流式产出（逐转移记录产出即释放，内存不随全量明细线性增长），
格式与语义细节见 [`docs/master_warehouse.md`](docs/master_warehouse.md) 第 3a 节。


四张逻辑表（稳定行键）：

| 表 | 行键 | 含义 |
| --- | --- | --- |
| `entity_map` | 原对象 ID | 原对象 → 组主键（组内 UTF-8 字节最小 ID） |
| `relations` | `(源主键, 关系类型, 目标主键)` | 归并有向关系与贡献数；双向不同行，自环带标识 |
| `contributions` | 原关系 ID | 原关系 → 归并键的贡献明细，含可回查原版坐标 |
| `verdicts` | 裁定 ID | 有效裁定及 `merged/already-same/blocked/constraint` 结果与阻挡证据 |

下游从一次完整读取取得四表与同一修订号，之后逐个消费 `master-changes`
即可恢复到最新内容，无需自行重算实体；未变化的行不会重发。后续批次只重算
变动端点经 `same` 候选（含被挡候选）可达的封闭区域，不重新扫包、不全量重算
分组、不全表扫描结果表（收据 `access` 与 EXPLAIN QUERY PLAN 可核查）。

## 3b. 主数据放行包（质量合同准入）

`master-release` 用一份 JSON 质量合同，从主数据仓**当前已提交头修订**生成一个
可直接装载的 SQLite 包：可装载区只保留通过准入的行，拒收账逐行说明哪一波、
哪一步失去资格。它不改裁定、不产生新修订，也不是两次修订的差异分析。格式、
语义与装载示例见 [`docs/master_release.md`](docs/master_release.md)。

```bash
# (18) 生成放行包（合同、主仓修订号、上游投影标识与合同摘要都写进包）
python3 -I sg-cli.py master-release \
  --master runtime/master_carol.sqlite \
  --contract tests/data/release_contract.example.json \
  --output runtime/release_carol.sqlite

# (19) 只读查看收据/波次账/逐行理由（不需要主仓）
python3 -I sg-cli.py master-release-read \
  --package runtime/release_carol.sqlite --what manifest
python3 -I sg-cli.py master-release-read \
  --package runtime/release_carol.sqlite --what entity \
  --entity malware--M1
python3 -I sg-cli.py master-release-read \
  --package runtime/release_carol.sqlite --what table --table reject_relations
```

要点：

- **准入不由人工裁定替代**：合同只声明允许发出的关系类型、明确排除的主实体
  ID、按实体类型登记的命名必需组；没有登记必需组的类型不受数量条件限制。
- **波次语义**：第 0 波先去掉合同明确排除的实体及其关联关系，再去掉不许发的
  关系类型；第 1 波及以后都对**同一份波前**判断，当波不满足者一起出局，只有
  下一波才把这次出局算进别人的支撑缺口；每条关系随第一个出局端点出局；没有
  新出局即稳定。互相支撑的闭环可留下，不要求连到人工选定的根。
- **对端去重**：规则从归并行认方向，按对端主实体 ID 去重——同一对端点之间
  不同类型的关系或多条来源贡献只算一个对端；自环不提供支撑，但类型许可且端点
  留存时照发。
- **可解释的拒收**：每个自动淘汰的实体记首次出局波、该波未满足的全部必需组、
  以及各备选项在波前实际的不同对端数与阈值；数字在该波判定时落盘，绝不用
  最终（可能为空的）图回填。
- **两区不重不漏**：三类输入行在可装载区与拒收账之间恰好各出现一次；留下的
  关系两端齐全、贡献可回查、`contribution_count` 与贡献行一致；合法空结果也
  是可装载包。
- **稳定可复跑**：同一视图与合同产生相同的逻辑表、理由与 `release_digest`；
  失败或崩溃不会留下可装载的新包，也不会破坏目标路径上已有的包；并发写入时
  包内只有一个已提交修订的行，不会混修订。
- **运维访问量**：支撑事实与逐波计数落在包内；建账后每一波只按主键读“已失去
  支撑对”的计数行，不再按波扫无关分区，也不会为一个失去的对端重扫整条高扇出
  邻接表。收据里每波的 `candidate_entities` / `probed_counter_rows` /
  `lost_support_pairs` 就是可复跑的访问量证据。

## 4. 一键独立核验

```bash
python3 -I tests/run_unit_verify.py     # 25 项：selector/redact 规则
python3 -I tests/run_verify.py          # 75 项：端到端授权矩阵/版本/边/令牌/导出
python3 -I tests/run_atomic_verify.py   # 10 项：失败不留半投影、中断不发代号
python3 -I tests/run_bulk_verify.py     # 18 项：2 万对象嵌套数组、内存有界
python3 -I tests/run_master_verify.py   # 95 项：主数据仓裁定/变更流/并发/崩溃/访问范围
python3 -I tests/run_impact_verify.py   # 124 项：修订影响分析/迁移分量/净变化/流式分页
python3 -I tests/run_release_verify.py  # 141 项：放行合同/波次/拒收理由/原子性/访问范围
```

主数据仓规模核验的无关分区数量可用环境变量调整（大库只在临时目录运行时生成，
不随仓库提交），用于证明纠错访问范围不随无关数据扩大：

```bash
SG_MASTER_SCALE=2000 python3 -I tests/run_master_verify.py
```

影响分析的大规模流式/分页核验规模可调（运行时合成于临时目录）：

```bash
SG_IMPACT_SCALE=2000 python3 -I tests/run_impact_verify.py
```

放行核验的长淘汰链、无关稳定分区与高扇出样例默认开大；关闭后用小型样例：

```bash
SG_RELEASE_SCALE=0 python3 -I tests/run_release_verify.py
```

大数据量可用环境变量调整规模：

```bash
SG_BULK_OBJECTS=50000 SG_BULK_WIDTH=60 \
  python3 -I tests/run_bulk_verify.py
```

## 5. 设计要点：为什么不是“在最终 JSON 删字段”

- 每个投影是独立 SQLite，包含 `objects`（投影后文档）、`search_terms`
  （仅由投影值建立的检索索引）、`edges`（两端皆可见的关系）、`meta`
  （身份与策略摘要、HMAC 签名密钥）。
- 受限原值在写入投影前就被丢弃：隐藏属性不插入，隐藏数组元素写 NULL，
  `search_terms` 跳过 NULL 与被删字段。因此即便有人直接打开投影文件做
  SQL/字节扫描，也取不到受限值（核验脚本含字节级断言）。
- NDJSON 接入逐行流式、finalize 用带索引临时表按身份逐组处理，95MB /
  2 万对象语料的 stage/finalize/project 峰值 RSS 均约 22–29MB，与语料
  大小不成比例增长，不把全仓常驻内存。

## 6. 合成数据声明

`tests/data` 与 `gen_bulk.py` 产出的全部为人工合成数据（虚构 id、标记、
pattern 字符串），不含任何真实情报或真实系统信息。
