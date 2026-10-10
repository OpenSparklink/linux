# QEMU usb-sle-dli Virtual Controller

QEMU 虚拟 SparkLink SLE DLI USB 控制器，用于在没有真实硬件的环境下
验证 Linux guest 的 USB transport 路径。

## 设计定位

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

### 与测试框架集成

```bash
# 方式一：指定自定义 QEMU + 启用设备
SLE_DLI_DEVICE=1 bash run_qemu_test.sh

# 方式二：指定自定义 QEMU 路径
QEMU_BIN=qemu-sle-dli/bin/bin/qemu-system-x86_64 \
SLE_DLI_DEVICE=1 bash run_qemu_test.sh
```

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

Use `run_runtime_lifecycle.py --native-ws73` for the production driver's native
URBs, Host credit/status handling and two-owner remove/re-add gate. Add
`--native-ws73-fault` for a malformed aggregate on A with B left usable. The
same runner's default standard-DLI test remains independent. See
`Documentation/networking/ws73-development.rst` for scope and commands.
