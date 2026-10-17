# QEMU usb-sle-dli Virtual Controller

QEMU 虚拟 SparkLink SLE DLI USB 控制器，用于在没有真实硬件的环境下
验证 Linux guest 的 USB transport 路径。

## 设计定位

`usb-ws73-test` 是另一个专用 runtime-only 测试设备，所有回复均为模拟。
`model-terminal-hold-once` 默认关闭，显式 arm 后保留队首下一份 DLI 终结帧；
Status、credit、其他帧不消费预算。`model-terminal-release` 交还原队首数据，
只读 held/holds/releases/bounded-releases/drops 记录状态；两秒 REALTIME timer
提供有界释放（实际调度并非硬实时）。预算跨 reset 保持，reset/drop/unrealize
清理 timer。它不保留真实 libusb transfer，不是 `usb-host` 的实际 IN81 hold，
也不是自然故障或 RF 证据。用于同一生产内核的 fd/迟到回复清理开发支撑，
真实设备验收必须仍使用实际 usb-host hold 门禁。

`model-terminal-skip-count` 是显式 uint64 配置，默认0、只接受0..2，且只能在
opened/idle、未 arm/hold/消费的对象上设置。前N份符合终结帧条件的数据按
原 USB 路径交还，不产生回复；只读 `model-terminal-skipped` 和原帧SHA日志
记录消费。之后仍只保留一份原队首帧并有界交还。Status/credit/其他帧不消费
skip预算，部分消费后reset也不能重配或重新arm。这为初始化后续步骤门禁
提供开发支撑；属性／函数检查自身不证明内核 fd 或真实在途 libusb 回复。

[后续步骤模型 VM 证据](https://github.com/OpenSparklink/sparklink/blob/4dd391f1b6689a50a85d20dc9f79602e6d8be55d/docs/evidence/ws73-managed-later-partial-model-fd-20261011.json)
另封存广告最后 STOP、扫描 START／最后 STOP × release／最后 fd／dup 九个
成功案例和三个精确拒绝。实际签名生产内核 fd、原期限、Cancelled、早期帧
及保留帧 SHA/长度逐一匹配；原最后 STOP 可确认 Off 而不重复 STOP／成功旧
请求。扫描 START 清理必须真的发送 STOP。原 VM FAIL 与错误保持，未修改
正式驱动／Rust。同行仍为模拟 Setup/Diagnostic；真实在途 libusb、活动
Ready 同伴、RF、自动恢复和自然根因尚未验收，不能据此关闭整项 issue。

```sh
python3 check-ws73-model-hold.py --cc clang --sanitize \
  --output /absolute/private/fresh-model-hold-check
```

该检查编译实际 retain/arm/release/reset 函数，计数依赖替代 timer/wakeup/digest，
验证默认值、过滤、队列字节保持、跨对象拒绝、显式/有界释放、后续帧选择、
类型/范围拒绝及 reset 不补预算。
它不验证 QEMU 调度、内核 fd 或真实 USB；这些须另跑相应 VM 门禁。

这不是一个完整的 SparkLink 射频仿真器。它的目标是：

- 对 guest 呈现符合 T/XS 10003-2025 的 USB DLI 控制器描述符
- 正确处理 guest 初始化序列（Reset / ReadLocalVersion / ReadMacAddr）
- 提供确定性的命令响应和事件生成
- 支持广播/扫描、连接/断开、固件下载等基本流程
- 支持故障注入（固件缺失、命令失败等）

## USB 描述符

按 T/XS 10003-2025 Table 3 和 Table 6：

| 字段 | 值 |
|------|----|
| bInterfaceClass | 0xE0 (Wireless Controller) |
| bInterfaceSubClass | 0x01 (RF Controller) |
| bInterfaceProtocol | 0x05 (SparkLink DLI) |
| Interrupt IN | 0x91, 16 bytes max |
| Bulk IN | 0x92, 64 bytes max |
| Bulk OUT | 0x12, 64 bytes max |

## 支持的命令

| Opcode | 名称 | 说明 |
|--------|------|------|
| 0x0401 | ReadCmdLen | 返回最大参数长度 255 |
| 0x0402 | ReadCtrlBuffer | 返回缓存容量 |
| 0x0403 | ReadLocalFeatures | 返回最小特性集 |
| 0x0404 | ReadLocalVersion | 返回协议版本、公司标识、子版本 |
| 0x0406 | ReadMacAddr | 返回 6 字节 MAC 地址 |
| 0x0408 | Reset | 重置控制器状态 |
| 0x0C05 | EnableBroadcast | 开启广播 |
| 0x0C06 | DisableBroadcast | 关闭广播 |
| 0x1002 | EnableScan | 开启扫描，生成 BroadcastReport |
| 0x1003 | DisableScan | 关闭扫描 |
| 0x1401 | CreateConnection | 创建连接 |
| 0x1403 | Disconnect | 断开连接 |
| 0xF810 | FwDownloadStart | 固件下载开始 |
| 0xF811 | FwDownloadDone | 固件下载完成 |

## 支持的事件

| Code | 名称 |
|------|------|
| 0x0001 | CommandStatus |
| 0x0002 | CommandComplete |
| 0x0005 | Disconnected |
| 0x000A | HardwareError |
| 0x0015 | ConnectionEstablished |
| 0x001A | BroadcastReport |

## 命令传输路径

设备支持两条命令路径：

1. **标准路径**：通过 EP0 类特定控制传输
2. **兼容路径**：通过 Bulk OUT (0x12) + Bulk IN (0x92)

guest 当前使用兼容路径进行初始化（通过 Bulk OUT 发送命令，
从 Bulk IN 同步读取响应），初始化完成后通过 Interrupt IN (0x91)
异步接收事件。

## 构建

```bash
cd tools/testing/selftests/sparklink/qemu-sle-dli
./build-qemu.sh
# Constrain build parallelism on a shared development machine.
JOBS=4 ./build-qemu.sh
```

构建脚本会：
1. 下载 QEMU 9.2.0 源码
2. 将 `usb-sle-dli.c` 复制到 `hw/usb/`
3. 修补 Kconfig 和 meson.build
4. 编译最小 x86_64-softmmu QEMU

构建产物在 `bin/bin/qemu-system-x86_64`。

真实 USB 开发客体需要 libusb 开发头文件与链接库；configure 现在显式
`--enable-libusb`，缺依赖时构建失败，不能把仅有模型的 QEMU 用作透传环境。
本机无 sudo 时可以将发行版已验证签名的开发 RPM 解包至工作区并配置
PKG_CONFIG_PATH，不安装到主机；保留实际依赖、私有 pc 修改及 runtime library hash。

构建脚本另应用 `usb-host-boundary.patch`。QEMU 的 host open-failure/close/exit
默认会 reset，打开和配置时会 detach kernel driver。新增
`kernel-driver-detach` / `host-reset` 两个 bool，默认 true 保留其他调用方行为。
WS73 实机 runner 同时设置两者 false、`guest-reset=false`、
`guest-resets-all=false`，并匹配固定 hostbus/hostport 和 vendorid=65535/
productid=14131。补丁禁止该对象的 detach/attach 与主机生命周期 reset；
guest reset 保持原独立开关。固件自身重新枚举和物理拔插仍照常发生。
已由其他驱动占用的接口不会因此被释放，guest 初始化可能失败，应保留错误。
默认 QEMU 没有这两个扩展属性；实机入口须拒绝并要求重建，不能静默省略。

另应用 `usb-host-retry.patch`，提供每对象 `host-retry` bool 脉冲，读回始终
false。true 仅在该对象无 libusb handle、未 attached 且使用 autoscan filter
时清零失败重试计数；后续仍由既有 autoscan timer 打开。已打开/附着对象收到
脉冲也不受影响，不触发 close/reset/detach，不修改其他对象或全局 timer。

另应用 `usb-host-reenumeration.patch`：固定 hostbus/hostport 的新设备地址
与已打开地址不同时，先调度现有 nodev BH 取消旧传输和关闭旧 handle，
由后续 autoscan 打开新 incarnation。旧 autoscan 会在 seen 后直接保留非空
旧 handle，实机出现 attached=true 但没有当前节点 live fd 的超时；新路径
已在实机固件重枚举后自动重新持有新节点。它不删除QMP对象，沿用上述
禁止主机reset/detach的边界；仅广泛VID/PID匹配的对象不受此规则影响。
地址复用为相同数值的情况并未由此谓词解决，不宣称所有重枚举故障已解决。
检查编译实际地址变化谓词并覆盖六种固定端口/地址/handle组合，验证三补丁
新应用、重复应用及逐个漂移拒绝。

两个物理 launcher 共用 `ws73-lab.py` 的非阻塞 ReattachmentWatcher：新地址
先等最多20秒，只有 attached 和该子进程当前USB节点的live fd均确认才更新
地址。udev/usbfs交接窗口继续等待；没有占用/attached/live fd且等待满6秒时
最多发一次 retry，仍不视为Ready。新的重新枚举重开计时；失踪设备不触发
删除，其他端口继续轮询；外部驱动、权限/所有权超时留下错误和记录。
禁止以 device_del/device_add 刷新物理对象，这会打断并发 auto-open/BSLE。
两个入口在 VM 启动前检查 host-retry 与原有边界/匹配属性，旧 binary 须重建。
这不修改内核 Ready 判据，也不证明真实拔插或 RF 成功。

检查实际生产函数体（libusb 调用由计数 mock 代替）、三处生命周期路由、
补丁的新应用/重复应用/漂移拒绝及可选实际二进制的 QMP 属性：

```sh
python3 check-usb-host-boundary.py \
  --source .build/qemu-9.2.0 \
  --qemu bin/bin/qemu-system-x86_64 \
  --output /absolute/private/fresh-usb-host-check
```

QMP 检查使用暂停的 TCG 客体，hostbus=255/hostport=255 与限定 VID/PID，
验证对象未 attached、VM 未运行、属性值可读回。它不选择主机设备，生产函数
mock 也不进行 libusb I/O；这两种检查均不证明真实透传/ROM/RF 或主机绑定竞争。
检查还编译真实 retry setter，覆盖 false、handle已开、已attached、非autoscan
拒绝、仅本对象恢复计数五种情况；暂停QMP验证脉冲读回false且仍未attached。
`python3 ../test_ws73_reattach.py` 提供16种确定性交接/超时/端口隔离测试。

`usb-host-runtime-error.patch`增加默认关闭的测试专用 QMP 脉冲
`test-runtime-in-error-once`及只读计数`test-runtime-in-errors`。只能在实际
ffff:3733 WS73 已 attached、handle有效且所有 reset/detach 开关关闭时显式
arm；下一次成功、非空的 bulk IN81 在 host/libusb 层已经完成，但其数据不交给
guest，改报 USB_RET_IOERROR。其他对象、端点、零长度和取消完成不消耗脉冲；
close清除未消费脉冲，不能跨到新 transport。禁止把这项人工注入计作自然故障
或物理拔插验收。内核 xHCI 可以先自行恢复端点，再由丢失回复导致命令超时；
需要同时保留 guest xHCI、QEMU生命周期、原始USB及协议诊断证据。

```sh
python3 check-usb-host-runtime-error.py \
  --source .build/qemu-9.2.0/hw/usb/host-libusb.c \
  --output /absolute/private/fresh-runtime-error-check
```

该检查编译实际callback/setter，使用计数mock验证默认行为、单次注入、
禁止arm条件及取消。autoscan检查还验证关闭一只设备只清除该设备的脉冲。
补丁应用工具先在临时树验证完整链，可升级零至七补丁的完整前缀；所有上下文
漂移检查完成前不修改调用者源码。暂停QMP检查拒绝对未attached对象arm。

`usb-host-runtime-hold.patch`提供单对象、默认关闭的成功接收暂留：显式设置
`test-runtime-in-hold-once=true`后，仅暂留下一份成功且非空的bulk IN81。
原libusb transfer、buffer和USBPacket保留，不改状态或数据、不生成回复。
日志保留长度和原始数据SHA256；`test-runtime-in-held`为只读状态。
`test-runtime-in-release=true`将原数据交给正常callback；`test-runtime-in-holds`、
`test-runtime-in-releases`、`test-runtime-in-bounded-releases`、
`test-runtime-in-hold-drops`均为只读计数。设置两秒REALTIME timer截止后自动释放；
实际执行仍取决于QEMU事件循环调度，不能宣称硬实时上限。
取消或close先清理timer/身份，再释放已完成transfer一次，不再向libusb取消它。
error/hold脉冲互斥；arm要求attached WS73和全部reset/detach关闭。
disarm仅取消尚未消费的脉冲，不能静默丢弃已暂留数据；release无实际暂留时拒绝。

```sh
python3 check-usb-host-runtime-hold.py \
  --source .build/qemu-9.2.0/hw/usb/host-libusb.c \
  --cc clang --sanitize \
  --output /absolute/private/fresh-runtime-hold-check
```

该检查编译实际hold/callback/abort/cancel/getter/setter，依赖由计数fixture提供；
覆盖默认行为、过滤、原数据交付、显式/有界释放、取消/abort/combined首包清理、
其他对象拒绝释放及arm互斥。timer、digest和combining是替身；实际QEMU调度、
完整close drain、多设备并发、线上取消/迟到回复/期限仍须独立VM真实设备门禁。
暂停QMP只验证默认/只读/拒绝arm与release，无USB匹配或guest运行。
这种暂留属于故障测试，不是自然故障根因或自主恢复验收。

`usb-host-enumeration-once.patch`增加默认关闭的 VM 实验属性
`test-enumeration-reset-once`。仅明确匹配 WS73 固定 hostbus/hostport，且原有
四个 reset/detach 开关全部关闭时可启用。只在 guest 地址为零且实际 handle
存在时，最多调用一次 libusb reset；调用前消费预算，失败也不补充。
只读 `test-enumeration-reset-used` 跨同一对象的关闭和重新枚举保持；不得删除
并重建对象来补预算。旧快照预算未知时禁止再复位；这不构成 live migration
资格。开启此实验时禁止 arm runtime error/hold，正式在途测试使用默认对象。
源码计数 fixture 和暂停 QMP 验证预算、默认值、只读及配置拒绝；真实复位次数、
描述符、固件上传和 Ready 必须另留 VM USB 证据。该开关不接入生产恢复。

完整开发门禁可由固定上游归档复现：

```sh
python3 run-usb-host-boundaries.py \
  --archive /absolute/qemu-9.2.0.tar.xz \
  --cc clang --output /absolute/private/fresh-qemu-host-boundaries
```

归档SHA256固定为
`f859f0bc65e1f533d040bbe8c92bcfecee5af2c921a6687c652fb44d089bd894`，
只读取两个指定源码成员，应用整条补丁链并执行实际函数依赖fixture；error/hold
启用ASan/UBSan。可另传`--qemu`进行上述暂停QMP检查。CI不编译完整QEMU、
不执行timer scheduler或真实USB；本地完整QEMU构建及实机门禁分开记录。

构建输出保留完整 configure/compiler/install 诊断。固定的 QEMU 9.2.0
包含仅用于构建的 libfdt const 声明修正，以兼容 glibc 2.43/GCC 16；
不改变虚拟控制器的协议行为。无 sudo 环境可使用工作区解包的官方
开发依赖及静态 BusyBox，设置 PKG_CONFIG_PATH/链接搜索路径；依赖来源、
版本、签名验证及实际构建环境须随运行记录保存。

## 使用

### 直接启动

```bash
# 使用自定义 QEMU 和虚拟控制器
./bin/bin/qemu-system-x86_64 \
    -kernel bzImage \
    -initrd initramfs.cpio.gz \
    -device qemu-xhci,id=xhci \
    -device usb-sle-dli,bus=xhci.0 \
    ...
```

### 当前测试入口

旧 `run_qemu_test.sh`／`run_runtime_lifecycle.py` 与 raw DLI 测试套件已归档到
`../retired-raw-uapi/`，不能用其历史 PASS 作为当前镜像资格。
当前默认 Core/Host/ledger 的实际 VM 入口为 `../run_virtual_vm.py`；
Native 部分初始化和 kernel-origin usercopy 使用 `../run_native_open_test.py`。
准确参数见各入口 `--help`，必须绑定匹配的 kernel、模块、工具与完整日志。
Virtual、合成 WS73 USB 和真实 WS73 是不同验收范围，不相互替代。

## 设备属性

| 属性 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| cmd-path | string | "dual" | 命令路径: dual / bulk-compat / control-only |
| fw-mode | string | "accept" | 固件模式: accept / missing / fail |

## 文件结构

```
qemu-sle-dli/
  usb-sle-dli.c    QEMU 设备源码
  build-qemu.sh    构建脚本
  README.md        本文档
```

## Synthetic native WS73 fixture

`usb-ws73-test.c` adds `-device usb-ws73-test` independently from the standard
`usb-sle-dli` model. It implements the runtime-only five-endpoint vendor
HCC/BSLE and metadata reply fixture. There is no boot ROM, firmware execution
or RF medium. Never use its synthetic configuration or metadata as hardware
calibration or real WS73 evidence.

The former raw-event lifecycle runner is archived, not a current gate.
The retained `run_native_open_test.py` uses typed DiagnosticSubmit/Result for
its synthetic WS73 survivor. Controlled USB-terminal, repeated-status and
recovery scenarios from the old runner require migration before new acceptance;
current Virtual tests do not claim all those hardware-driver scenarios.

The historical runner's `--native-ws73-tx-barrier` independently enables `runtime-out-delay-ms=2000` on
the first fixture. It defers the first post-bootstrap ReadLocalFeatures OUT
using an asynchronous USB packet while delivering the device Complete on IN.
Read-only `runtime-out-pending` and `runtime-out-replied` properties provide the
host/guest UART barrier. The timer completes the held packet; packet cancellation
removes that timer and reference. The delay is off by default and limited to
2000 ms, below the production driver's OUT timeout. This is a transport race
fixture; it does not execute firmware or provide RF evidence.

`--native-ws73-tx-terminal out-error|short-out|unplug` reuses that pending-reply
barrier. `runtime-out-result=1` returns STALL after the early reply;
`runtime-out-result=2` completes one byte short. Both require the opt-in delay,
and the default remains normal completion. `unplug` verifies the packet is
still pending immediately before deleting the synthetic device. Packet
cancellation clears its timer/pointer; a late completion would fail the gate.
The guest rejects early success, observes owner retirement, driver error and
survivor isolation, then retains old raw/event fds through replacement and a
measured 2200 ms guard. These modes are standalone synthetic tests and cannot
certify physical WS73 unplug or receiver RF.


Warm-adoption fixture: `runtime-warm=true` suppresses the one-shot BSP interrupt
and queues stale BOOT/CLOSE frames. Only a new CLOSE30 acknowledgement and fresh
customize/open handshake may complete the one-attempt recovery. The default is
false. `runtime-idle-scan-stop=true` returns raw0b on OFF while not scanning;
this is an explicit synthetic model of the observed111 failure, not RF proof.
The companion support runner enables it and exercises passive initializer6.
Keep failures in lease cleanup/writer probes visible; older synthetic receipts
with unconditional OFF success do not cover these preconditions.

### Actual host frame selector for later initialization steps

The explicit development QMP selectors `test-runtime-in-skip-one` and
`test-runtime-in-skip-two` configure at most two successful nonempty bulk IN81
frames to deliver through the normal callback before retaining the next original
frame. All selectors default disabled. Three read-only counters expose requested,
remaining and skipped counts. Each skipped frame logs the original length and
SHA256 with host status zero; no buffer, status or DLI event is fabricated.

Configuration requires an idle attached WS73 and all reset/detach/enumeration
experiments disabled. It is rejected during hold/error injection. Wrong endpoint,
failed/empty/non-bulk or cancelled callbacks do not consume this budget. Close
clears the selector before aborting transfers. The existing two-second bounded
hold remains, and kernel operation deadlines are never extended.

`check-usb-host-runtime-hold.py` covers the actual selector/callback/setter code
with counted dependency fixtures and can run ASan/UBSan. Those tests and QMP
qualification do not establish real USB, scheduler, radio or automatic recovery
acceptance. Later physical gates must match every skipped and retained frame
hash/length to the actual capture and retain independent Ready peer activity.

## Explicit original held-frame drop diagnostics

`usb-host-runtime-drop.patch` adds a test-only log before the already-completed
held transfer is freed by either request abort or packet cancellation. It records
host bus/address, original length, drop count and SHA256. It does not copy a
payload to the guest or create a successful USB/DLI completion. Default-disabled
hold behavior is unchanged; timers and held identity are cleared before freeing.
This allows QMP device deletion to archive evidence even after the object and
its read-only counters are gone.

The actual callback fixture covers cancel, live abort, dead abort and combined
cancellation, requiring four ordered original-frame drop logs, no payload copy,
no libusb re-cancellation, no timer replay and one free per allocation. Digest,
timer, transport and USB combining dependencies remain explicit counted
fixtures, not real USB or QEMU scheduler qualification. Run the pinned boundary
chain with ASan/UBSan/LSan; every prior complete patch prefix is supported, and
DROP log context drift must be rejected without mutating the caller's source.
Actual cancellation/removal, physical hotplug and natural nonmanual recovery
still require separate VM/hardware gates.

### SDK111 installation-reply selection (test fixture)

`usb-host-runtime-install.patch` adds default-disabled `test-runtime-install-g`
(0x1c03) / `test-runtime-install-t` (0x1c05) selectors and the read-only
`test-runtime-install-opcode`. Configure only an idle, attached ffff:3733
controller with every reset/detach opt-out. The selector and frame-skip/error
injection are mutually exclusive. Then arm the existing
`test-runtime-in-hold-once` mechanism. Nonmatches use the unchanged ordinary
callback; this is not an event generator or a second Host.

The selector validates the complete bounded HCC aggregate, not a byte substring
or frame number. It retains the original successful IN81 transfer containing an
SDK111 service-A/queue-8 A2 Status or Complete with exactly four parameter bytes:
selected opcode, credit 1, status 0. Other completion layouts are deliberately
not selected. Malformed aggregates, padding, other opcodes/roles and failed
Status do not consume the arm. The existing two-second REALTIME fallback,
explicit release, cancellation, drop and close/drain ownership remain in use.
Close clears selection before aborting transfers. Selection identifies an
opcode, **not** generation/lifetime: the eventual VM witness must independently
correlate the original request, actual installation submission, exact held
transfer hash, release and terminal observations. Coalesced events in that same
transfer are delayed together, never split or reordered by the fixture.

Run the actual callback/setter body checks with counted dependencies:

```sh
python3 check-usb-host-runtime-hold.py --cc clang --sanitize \
  --source /absolute/patched-qemu/hw/usb/host-libusb.c \
  --output /absolute/private/fresh-install-selector-check
```

This includes both role selectors, unchanged nonmatching callbacks, truncated
exact allocations, aggregate-tail validation and existing release/cancel/abort
checks. Timers, QEMU scheduling, digest, USB and allocator integration remain
outside the counted fixture. Run `check-usb-host-boundary.py` separately for
fresh/prefix/idempotent patch application and drift refusal, optionally against
the actual binary in a paused TCG guest matching no physical device. Neither
check qualifies live in-flight cancellation, encryption, peer delivery or
natural recovery; those need separate VM-only real-device gates.

### Current Native lifecycle and credential runners

`run_native_open_test.py` and `run_daemon_lifecycle.py` consume the sealed
`NATIVE_BUILD_ARTIFACTS_VERIFIED` receipt and verify every input's hash and size.
Pass `--qemu-data` explicitly; modular kernels also require a matching signed
`--ws73-module`. Build the Native open fixture separately under the shared
resource budget and pass `--fixture-module`; runners never build or load a host
module. See `--help` and the current commands in `ws73-development.rst`.

`check-ws73-model-chip.py --output <fresh-directory> --sanitize` exercises the
actual model dispatch/queue and production HCC/request/reply parser. Its clock
and controller state are explicit fixtures. The runtime chip response is a
synthetic U/USB sample, not ROM identification or chip authentication. The
full-frame check retains the rejected PLAT subtype counterexample; payload-only
checking cannot establish HCC compatibility. No command fallback is generated.

The credential runner can exercise the production policy on a private bus;
this does not establish system-bus installation, udev deployment, real firmware,
RF delivery or nonmanual recovery. Native management statistics remain
unsupported. Typed replay and immutable snapshot checks replace the obsolete
counter projection; they do not prove physical debt conservation.
