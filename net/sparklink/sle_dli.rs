// SPDX-License-Identifier: GPL-2.0

//! SparkLink Driver Layer Interface (DLI).
//!
//! Internal metadata and standard event definitions for registered providers.
//! Drivers register a retained Backend descriptor. The unique Runtime Host
//! owns command admission, protocol credit and physical reply obligations;
//! its worker submits through CommandPort and actual commit tickets.
//! The small SleController view supplies metadata and joined close only.
//!
//! Production event values have an explicit Host or Native worker consumer.
//! Standard-profile command replies/credits and critical HardwareError are
//! supported; unconsumed historical business events are isolated in selftests.
//! Connected WS73 data and security retain their Native lifetime-bound ingress;
//! packet names do not imply support for synchronous or multicast modes.
//!
//! Opcode encoding follows TXS-10003-2025: upper 6 bits = command
//! group (OGF), lower 10 bits = command within the group (OCF).

#![deny(dead_code, unreachable_pub)]

use kernel::alloc::KVec;
use kernel::prelude::*;

// ---------------------------------------------------------------------------
// Controller backend event ring capacity
// ---------------------------------------------------------------------------

/// Number of slots in each controller backend's event ring buffer.
/// Must be a power of two for efficient modular arithmetic.
pub(crate) const CTRL_EVENT_RING_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Shared event ring for hardware controller backends
// ---------------------------------------------------------------------------

/// Thread-safe event ring buffer used by the remaining generic USB controller to
/// buffer asynchronous events received from hardware completion callbacks
/// through the registration-owned ingress; the owner RX worker drains them.
pub(crate) struct ControllerEventRing {
    events: [(Option<u16>, Option<SleEvent>); CTRL_EVENT_RING_SIZE],
    head: usize,
    tail: usize,
    /// Cumulative count of events dropped due to ring overflow.
    pub(crate) dropped: u32,
}

impl ControllerEventRing {
    /// Initialize the ingress array in its final heap allocation.
    pub(crate) fn new_boxed() -> Result<KBox<Self>> {
        KBox::init(init!(Self {
            events <- pin_init::init_array_from_fn(|_| (None, None)),
            head: 0,
            tail: 0,
            dropped: 0,
        }), GFP_KERNEL)
    }

    /// Push an event with an optional source device id.
    /// Returns `true` if the event was stored, `false` if dropped (ring full).
    pub(crate) fn push_tagged(&mut self, dev_id: Option<u16>, ev: SleEvent) -> bool {
        let next = (self.tail + 1) % CTRL_EVENT_RING_SIZE;
        if next == self.head {
            self.dropped = self.dropped.wrapping_add(1);
            return false;
        }
        self.events[self.tail] = (dev_id, Some(ev));
        self.tail = next;
        true
    }

    /// Pop the next event along with its source device id.
    pub(crate) fn pop_tagged(&mut self) -> Option<(Option<u16>, SleEvent)> {
        if self.head == self.tail {
            return None;
        }
        let (dev_id, ev) = core::mem::take(&mut self.events[self.head]);
        self.head = (self.head + 1) % CTRL_EVENT_RING_SIZE;
        ev.map(|e| (dev_id, e))
    }
}

// ---------------------------------------------------------------------------
// Provider registration metadata, not protocol capability state
// ---------------------------------------------------------------------------

/// Validated provider provenance. Reserved public bus numbers are not supported
/// providers: only USB and the explicit test provider are constructible here.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum SleBus {
    None = 0,
    Usb = 4,
    Test = 6,
}

/// Registration observation only. Runtime/Native snapshots own queried wire
/// capabilities and retain the full version/feature tuples. No inferred MTU,
/// mode, security policy or independently writable Ready state belongs here.
pub(crate) struct SleControllerInfo {
    /// Validated provider provenance; None is an unpopulated reservation.
    pub bus: SleBus,
    /// Observed address, or zero before bootstrap.
    pub addr: [u8; 6],
}

impl Default for SleControllerInfo {
    fn default() -> Self {
        Self { bus: SleBus::None, addr: [0; 6] }
    }
}

/// Well-known DLI command opcodes from T/XS 10003-2025.
///
/// Encoded as `(OGF << 10) | OCF` following the standard.
/// Group numbers in comments follow the standard document sections.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum SleOpcode {
    // --- Group 1: Basic (OGF=0x01, wire 0x04xx, section 8.1) ---
    /// 读控制器指令长度 (8.1.1)
    ReadCmdLen = 0x0401,
    /// 读控制器缓存 (8.1.2)
    ReadCtrlBuffer = 0x0402,
    /// 读本地特性 (8.1.3)
    ReadLocalFeatures = 0x0403,
    /// 读本地版本信息 (8.1.4)
    ReadLocalVersion = 0x0404,
    /// 设置媒体接入层唯一标识 (8.1.5)
    SetMacAddr = 0x0405,
    /// 读媒体接入层标识 (8.1.6)
    ReadMacAddr = 0x0406,
    /// 设置媒体接入层非唯一标识 (8.1.7)
    SetNonUniqueMac = 0x0407,
    /// 控制器复位 (8.1.8)
    Reset = 0x0408,
    /// 可用信道指示 (8.1.9)
    AvailChannelInd = 0x0409,
    /// 读白名单大小 (8.1.10)
    ReadWhitelistSize = 0x040A,
    /// 清空白名单 (8.1.11)
    ClearWhitelist = 0x040B,
    /// 添加白名单设备 (8.1.12)
    AddWhitelist = 0x040C,
    /// 删除白名单设备 (8.1.13)
    DeleteWhitelist = 0x040D,
    /// 设置SLB节点角色 (8.1.14)
    SetSlbNodeRole = 0x040E,
    /// 读SLB节点角色 (8.1.15)
    ReadSlbNodeRole = 0x040F,
    /// 设置SLB工作信道 (8.1.16)
    SetSlbWorkChannel = 0x0410,
    /// 读SLB工作信道 (8.1.17)
    ReadSlbWorkChannel = 0x0411,
    /// 读SLB控制器缓存 (8.1.18)
    ReadSlbCtrlBuffer = 0x0412,
    /// 配置FISA信道列表 (8.1.19)
    ConfigFisaChannels = 0x0413,
    /// 使能FISA (8.1.20)
    EnableFisa = 0x0414,
    /// 配置SLB同步信号 (8.1.21)
    ConfigSlbSyncSignal = 0x0415,
    /// 读SLB同步信号配置 (8.1.22)
    ReadSlbSyncSignal = 0x0416,
    /// 读SLB本地功率 (8.1.23)
    ReadSlbLocalPower = 0x0417,
    /// 使能SLB控制器 (8.1.24)
    EnableSlbCtrl = 0x0418,
    /// 指示时间同步状态 (8.1.25)
    IndicateTimeSync = 0x0419,
    /// 时间同步请求 (8.1.26)
    TimeSyncRequest = 0x041A,
    /// 时间同步响应 (8.1.27)
    TimeSyncResponse = 0x041B,
    /// 添加白名单设备扩展 (8.1.28)
    AddWhitelistExt = 0x0420,

    // --- Group 3: Broadcast (OGF=0x03, wire 0x0Cxx, section 8.2) ---
    /// 配置广播参数 (8.2.1)
    SetBroadcastParam = 0x0C02,
    /// 配置广播数据 (8.2.2)
    SetBroadcastData = 0x0C03,
    /// 配置查询回复数据 (8.2.3)
    SetBroadcastScanRsp = 0x0C04,
    /// 使能广播 (8.2.4)
    EnableBroadcast = 0x0C05,
    /// 读最大广播数据长度 (8.2.5)
    ReadMaxBcastDataLen = 0x0C06,
    /// 读广播集合大小 (8.2.6)
    ReadBcastSetSize = 0x0C07,
    /// 删除广播集合 (8.2.7)
    DeleteBcastSet = 0x0C08,
    /// 配置SLB通信域域名 (8.2.8)
    ConfigSlbDomainName = 0x0C09,
    /// 读SLB通信域域名 (8.2.9)
    ReadSlbDomainName = 0x0C0A,
    /// 配置SLB广播参数 (8.2.10)
    ConfigSlbBcastParam = 0x0C0B,
    /// 读SLB广播参数 (8.2.11)
    ReadSlbBcastParam = 0x0C0C,

    // --- Group 4: Scan/Query (OGF=0x04, wire 0x10xx, section 8.3) ---
    /// 设置查询参数 (8.3.1)
    SetScanParam = 0x1001,
    /// 使能查询 (8.3.2)
    EnableScan = 0x1002,
    /// 设置查询请求数据 (8.3.3)
    SetScanReqData = 0x1003,
    /// 设置SLB查询参数 (8.3.4)
    SetSlbScanParam = 0x1004,

    // --- Group 5: Connection (OGF=0x05, wire 0x14xx, section 8.4) ---
    /// 创建异步链路 (8.4.1)
    CreateConnection = 0x1401,
    /// 取消异步链路建立 (8.4.2)
    CancelConnection = 0x1402,
    /// 断开连接 (8.4.3)
    Disconnect = 0x1403,
    /// SLB创建连接 (8.4.4)
    SlbCreateConnection = 0x1404,

    // --- Group 6: Link control (OGF=0x06, wire 0x18xx, section 8.5) ---
    /// 读取对端特性 (8.5.1)
    ReadFeatures = 0x1801,
    /// 读取对端版本信息 (8.5.2)
    ReadVersion = 0x1802,
    /// 设置数据长度 (8.5.3)
    SetMaxDataLen = 0x1804,
    /// 读取物理层参数 (8.5.4)
    ReadPhyParam = 0x1805,
    /// 设置物理层参数 (8.5.5)
    SetPhyParam = 0x1806,
    /// 连接参数更新 (8.5.6)
    ConnParamUpdate = 0x1807,
    /// 设置对端连接参数更新请求的响应 (8.5.7)
    ConnParamReqReply = 0x1808,
    /// 读取可用信道 (8.5.8)
    ReadAvailChannels = 0x1809,
    /// 设置编码调制参数 (8.5.9)
    SetCodingModulation = 0x180A,
    /// 读取RSSI (8.5.10)
    ReadRssi = 0x180C,
    /// 设置本端功率 (8.5.11)
    SetTxPower = 0x180D,
    /// 读取本端功率 (8.5.12)
    ReadTxPower = 0x180E,
    /// 读取对端功率 (8.5.13)
    ReadPeerTxPower = 0x180F,
    /// 功率变化报告配置 (8.5.14)
    ConfigPowerReport = 0x1810,
    /// 设置控制器控制信令数据 (8.5.15)
    SetCtrlSignalData = 0x1812,
    /// 开启RSSI功率控制 (8.5.16)
    EnableRssiPowerCtrl = 0x1813,
    /// 设置SLB编码调制参数 (8.5.17)
    SetSlbCodingMod = 0x1814,
    /// 读取SLB编码调制参数 (8.5.18)
    ReadSlbCodingMod = 0x1815,

    // --- Group 7: Security (OGF=0x07, wire 0x1Cxx, section 8.6) ---
    /// 散列计算 (8.6.1)
    HashCompute = 0x1C01,
    /// 生成安全随机数 (8.6.2)
    GenSecureRandom = 0x1C02,
    /// 启动链路加密 (8.6.3)
    StartEncrypt = 0x1C03,
    /// 请求配对 (8.6.4)
    RequestPair = 0x1C04,
    /// 回复链路加密参数请求 (8.6.5)
    ReplyEncParamReq = 0x1C05,
    /// 拒绝链路加密参数请求 (8.6.6)
    RejectEncParamReq = 0x1C06,
    /// 读取本端加密算法 (8.6.7)
    ReadLocalEncAlgo = 0x1C07,
    /// 启动配对 (8.6.8)
    StartPairing = 0x1C08,
    /// 配对信息交换回复 (8.6.9)
    PairInfoExchange = 0x1C09,
    /// 配对选项确认 (8.6.10)
    PairOptionConfirm = 0x1C0A,
    /// 配对选项接受 (8.6.11)
    PairOptionAccept = 0x1C0B,
    /// 配对扩展数据 (8.6.12)
    PairExtData = 0x1C0C,
    /// 用户通行码按键 (8.6.13)
    PairPasskey = 0x1C0D,
    /// 配对随机数 (8.6.14)
    PairRandom = 0x1C0E,
    /// 配对确认码 (8.6.15)
    PairConfirm = 0x1C0F,
    /// DHKey验证 (8.6.16)
    DhkeyVerify = 0x1C10,
    /// 配对失败 (8.6.17)
    PairFail = 0x1C11,
    /// 添加设备至RAL (8.6.18)
    AddRalDevice = 0x1C12,
    /// 从RAL删除设备 (8.6.19)
    RemoveRalDevice = 0x1C13,
    /// 清空RAL (8.6.20)
    ClearRal = 0x1C14,
    /// 读取RAL大小 (8.6.21)
    ReadRalSize = 0x1C15,
    /// 读对端可解析随机标识 (8.6.22)
    ReadRemoteRpa = 0x1C16,
    /// 读本端可解析随机标识 (8.6.23)
    ReadLocalRpa = 0x1C17,
    /// 设置RPA使能 (8.6.24)
    SetRpaEnable = 0x1C18,
    /// 设置RPA超时时间 (8.6.25)
    SetRpaTimeout = 0x1C19,
    /// 配置SLB认证PSK (8.6.26)
    ConfigSlbAuthPsk = 0x1C1A,
    /// 删除SLB认证PSK (8.6.27)
    DeleteSlbAuthPsk = 0x1C1B,
    /// 配置SLB认证口令 (8.6.28)
    ConfigSlbAuthPwd = 0x1C1C,
    /// 删除SLB认证口令 (8.6.29)
    DeleteSlbAuthPwd = 0x1C1D,
    /// 配置SLB密码算法 (8.6.30)
    ConfigSlbCipherAlgo = 0x1C1E,
    /// 读取SLB密码算法 (8.6.31)
    ReadSlbCipherAlgo = 0x1C1F,
    /// 配置SLB安全关联数量 (8.6.32)
    ConfigSlbSecAssoc = 0x1C20,
    /// 读取SLB安全关联数量 (8.6.33)
    ReadSlbSecAssoc = 0x1C21,
    /// 配置SLB安全绑定过期时间 (8.6.34)
    ConfigSlbSecTimeout = 0x1C22,
    /// 读取SLB安全绑定过期时间 (8.6.35)
    ReadSlbSecTimeout = 0x1C23,

    // --- Group 8: Measurement (OGF=0x08, wire 0x20xx, section 8.7) ---
    /// 读取本地测量能力 (8.7.1)
    ReadLocalMeasCap = 0x2001,
    /// 设置测量链路参数 (8.7.2)
    SetMeasLinkParam = 0x2003,
    /// 测量动作 (8.7.3)
    MeasAction = 0x2005,
    /// 使能测量 (8.7.4)
    EnableMeas = 0x200B,

    // --- Group 9: SLB Logical Channel (OGF=0x09, wire 0x24xx, section 8.8) ---
    /// 创建SLB单播逻辑信道 (8.8.1)
    SlbCreateLogChannel = 0x2401,
    /// 更新SLB单播逻辑信道 (8.8.2)
    SlbUpdateLogChannel = 0x2402,
    /// 删除SLB逻辑信道 (8.8.3)
    SlbDeleteLogChannel = 0x2403,

    // --- Group 10: Sync link (OGF=0x0A, wire 0x28xx, section 8.10) ---
    /// 同步单播链路配置 (8.10.1)
    SyncUcastParam = 0x2801,
    /// 同步单播链路创建 (8.10.3)
    SyncUcastCreate = 0x2803,
    /// 同步单播链路移除 (8.10.4)
    SyncUcastRemove = 0x2804,
    /// 接受同步单播建链 (8.10.5)
    SyncUcastAccept = 0x2805,
    /// 拒绝同步单播建链 (8.10.6)
    SyncUcastReject = 0x2806,
    /// 设置同步组播参数 (8.10.7)
    SyncMcastParam = 0x2807,
    /// 设置同步组播链路信息 (8.10.8)
    SyncMcastInfo = 0x2808,
    /// 创建同步组播链路 (8.10.9)
    SyncMcastCreate = 0x2809,
    /// 同步组播链路信息移除 (8.10.10)
    SyncMcastRemove = 0x280A,
    /// 接受同步组播链路建链 (8.10.11)
    SyncMcastAccept = 0x280B,
    /// 拒绝同步组播链路建链 (8.10.12)
    SyncMcastReject = 0x280C,
    /// 同步链路数据路径配置 (8.10.13)
    SyncDataPathConfig = 0x280D,
    /// 同步链路数据路径删除 (8.10.14)
    SyncDataPathRemove = 0x280E,

    // --- Group 62: Test (OGF=0x3E, wire 0xF8xx, section 8.9) ---
    /// 测试模式使能 (8.9.1)
    TestModeEnable = 0xF801,
    /// 测试接收 (8.9.2)
    TestRx = 0xF802,
    /// 测试发送 (8.9.3)
    TestTx = 0xF803,
    /// 测试接收结果 (8.9.4)
    TestRxResult = 0xF804,

    // --- Vendor extension (OGF=0x3F, wire 0xFCxx-0xFFFF) ---
    /// 厂商自定义指令基址
    VendorBase = 0xFC00,
}

/// Completion status for a command.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum SleStatus {
    Success = 0x00,
    UnknownCommand = 0x01,
    InvalidParameters = 0x02,
    HardwareFailure = 0x03,
    ResourceExhausted = 0x04,
    NotConnected = 0x05,
    AlreadyActive = 0x06,
    PermissionDenied = 0x07,
    Timeout = 0x08,
}

// ---------------------------------------------------------------------------
// Consumed event model (wire validation remains in sle_standard_dli)
// ---------------------------------------------------------------------------

/// An event from the controller to the host.
pub(crate) enum SleEvent {
    /// Unsolicited credit update, never a transaction result.
    CommandCredits { credits: u8 },
    /// Standard-profile completed command;author resolved by the Host.
    CommandComplete {
        opcode: SleOpcode,
        command_credits: u8,
        status: SleStatus,
        data: KVec<u8>,
    },
    /// Standard-profile pending/failure status.
    CommandStatus {
        opcode: SleOpcode,
        command_credits: u8,
        status: SleStatus,
    },
    /// Exact Native dialect opcode/status;not an enum alias.
    NativeCommandReply {
        opcode: u16,
        command_credits: u8,
        status: u8,
        complete: bool,
        data: KVec<u8>,
    },
    /// Native relay payload with ingress-frozen lifetime.
    NativeControllerData { lifetime:u64, handle:u16, index:u16, data:KVec<u8> },
    /// Actual installation observation with ingress-frozen lifetime/revision.
    NativeSecurityInstallation {lifetime:u64, security_revision:u64, handle:u16, event:u16, status:u8, enabled:u8},
    /// Controller-scoped critical fault;cannot infer a connection handle.
    HardwareError { code: u8 },
}

// ---------------------------------------------------------------------------
// Registered provider metadata/close view
// ---------------------------------------------------------------------------

/// Borrowed metadata and joined transport close for the registered provider.
/// Commands use the retained CommandPort and identity-bound Host tickets;
/// transport open belongs to Runtime open, never application fd construction.
pub(crate) trait SleController: Send + Sync {
    fn info(&self) -> SleControllerInfo;
    fn close(&self);
}

// ---------------------------------------------------------------------------
// Controller dispatch enum (avoids trait objects)
// ---------------------------------------------------------------------------

/// Common registered provider. Bus/dialect live in validated descriptor metadata,
/// not in independent USB/WS73 installation or lifetime implementations.
pub(crate) enum ControllerBackend {
    Native(super::sle_native::NativeController),
}

// SAFETY: ControllerBackend is stored in ControllerState under each Runtime state mutex.
//  The Mutex provides exclusive access, so Cell/RefCell
// interior mutability in the contained controllers is sound.
unsafe impl Send for ControllerBackend {}
// SAFETY: ControllerBackend is stored in ControllerState under each Runtime state mutex.
//  The Mutex provides exclusive access, so Cell/RefCell
// interior mutability in the contained controllers is sound.
unsafe impl Sync for ControllerBackend {}

impl ControllerBackend {
    pub(crate) fn provider(&self) -> &super::sle_native::NativeController {
        let Self::Native(provider) = self;
        provider
    }
    pub(crate) fn provider_mut(&mut self) -> &mut super::sle_native::NativeController {
        let Self::Native(provider)=self;
        provider
    }
}

// -- High-level convenience wrappers ----------------------------------------
// These encapsulate DLI parameter encoding so the core layer never builds
// transport-level byte arrays directly (T/XS 10003-2025 section 8).

/// Convert a raw u16 to SleOpcode, returning None for unknown values.
pub(crate) fn sle_opcode_from_u16(v: u16) -> Option<SleOpcode> {
    match v {
        0x0401 => Some(SleOpcode::ReadCmdLen),
        0x0402 => Some(SleOpcode::ReadCtrlBuffer),
        0x0403 => Some(SleOpcode::ReadLocalFeatures),
        0x0404 => Some(SleOpcode::ReadLocalVersion),
        0x0405 => Some(SleOpcode::SetMacAddr),
        0x0406 => Some(SleOpcode::ReadMacAddr),
        0x0407 => Some(SleOpcode::SetNonUniqueMac),
        0x0408 => Some(SleOpcode::Reset),
        0x0409 => Some(SleOpcode::AvailChannelInd),
        0x040A => Some(SleOpcode::ReadWhitelistSize),
        0x040B => Some(SleOpcode::ClearWhitelist),
        0x040C => Some(SleOpcode::AddWhitelist),
        0x040D => Some(SleOpcode::DeleteWhitelist),
        0x040E => Some(SleOpcode::SetSlbNodeRole),
        0x040F => Some(SleOpcode::ReadSlbNodeRole),
        0x0410 => Some(SleOpcode::SetSlbWorkChannel),
        0x0411 => Some(SleOpcode::ReadSlbWorkChannel),
        0x0412 => Some(SleOpcode::ReadSlbCtrlBuffer),
        0x0413 => Some(SleOpcode::ConfigFisaChannels),
        0x0414 => Some(SleOpcode::EnableFisa),
        0x0415 => Some(SleOpcode::ConfigSlbSyncSignal),
        0x0416 => Some(SleOpcode::ReadSlbSyncSignal),
        0x0417 => Some(SleOpcode::ReadSlbLocalPower),
        0x0418 => Some(SleOpcode::EnableSlbCtrl),
        0x0419 => Some(SleOpcode::IndicateTimeSync),
        0x041A => Some(SleOpcode::TimeSyncRequest),
        0x041B => Some(SleOpcode::TimeSyncResponse),
        0x0420 => Some(SleOpcode::AddWhitelistExt),
        0x0C02 => Some(SleOpcode::SetBroadcastParam),
        0x0C03 => Some(SleOpcode::SetBroadcastData),
        0x0C04 => Some(SleOpcode::SetBroadcastScanRsp),
        0x0C05 => Some(SleOpcode::EnableBroadcast),
        0x0C06 => Some(SleOpcode::ReadMaxBcastDataLen),
        0x0C07 => Some(SleOpcode::ReadBcastSetSize),
        0x0C08 => Some(SleOpcode::DeleteBcastSet),
        0x0C09 => Some(SleOpcode::ConfigSlbDomainName),
        0x0C0A => Some(SleOpcode::ReadSlbDomainName),
        0x0C0B => Some(SleOpcode::ConfigSlbBcastParam),
        0x0C0C => Some(SleOpcode::ReadSlbBcastParam),
        0x1001 => Some(SleOpcode::SetScanParam),
        0x1002 => Some(SleOpcode::EnableScan),
        0x1003 => Some(SleOpcode::SetScanReqData),
        0x1004 => Some(SleOpcode::SetSlbScanParam),
        0x1401 => Some(SleOpcode::CreateConnection),
        0x1402 => Some(SleOpcode::CancelConnection),
        0x1403 => Some(SleOpcode::Disconnect),
        0x1404 => Some(SleOpcode::SlbCreateConnection),
        0x1801 => Some(SleOpcode::ReadFeatures),
        0x1802 => Some(SleOpcode::ReadVersion),
        0x1804 => Some(SleOpcode::SetMaxDataLen),
        0x1805 => Some(SleOpcode::ReadPhyParam),
        0x1806 => Some(SleOpcode::SetPhyParam),
        0x1807 => Some(SleOpcode::ConnParamUpdate),
        0x1808 => Some(SleOpcode::ConnParamReqReply),
        0x1809 => Some(SleOpcode::ReadAvailChannels),
        0x180A => Some(SleOpcode::SetCodingModulation),
        0x180C => Some(SleOpcode::ReadRssi),
        0x180D => Some(SleOpcode::SetTxPower),
        0x180E => Some(SleOpcode::ReadTxPower),
        0x180F => Some(SleOpcode::ReadPeerTxPower),
        0x1810 => Some(SleOpcode::ConfigPowerReport),
        0x1812 => Some(SleOpcode::SetCtrlSignalData),
        0x1813 => Some(SleOpcode::EnableRssiPowerCtrl),
        0x1814 => Some(SleOpcode::SetSlbCodingMod),
        0x1815 => Some(SleOpcode::ReadSlbCodingMod),
        0x1C01 => Some(SleOpcode::HashCompute),
        0x1C02 => Some(SleOpcode::GenSecureRandom),
        0x1C03 => Some(SleOpcode::StartEncrypt),
        0x1C04 => Some(SleOpcode::RequestPair),
        0x1C05 => Some(SleOpcode::ReplyEncParamReq),
        0x1C06 => Some(SleOpcode::RejectEncParamReq),
        0x1C07 => Some(SleOpcode::ReadLocalEncAlgo),
        0x1C08 => Some(SleOpcode::StartPairing),
        0x1C09 => Some(SleOpcode::PairInfoExchange),
        0x1C0A => Some(SleOpcode::PairOptionConfirm),
        0x1C0B => Some(SleOpcode::PairOptionAccept),
        0x1C0C => Some(SleOpcode::PairExtData),
        0x1C0D => Some(SleOpcode::PairPasskey),
        0x1C0E => Some(SleOpcode::PairRandom),
        0x1C0F => Some(SleOpcode::PairConfirm),
        0x1C10 => Some(SleOpcode::DhkeyVerify),
        0x1C11 => Some(SleOpcode::PairFail),
        0x1C12 => Some(SleOpcode::AddRalDevice),
        0x1C13 => Some(SleOpcode::RemoveRalDevice),
        0x1C14 => Some(SleOpcode::ClearRal),
        0x1C15 => Some(SleOpcode::ReadRalSize),
        0x1C16 => Some(SleOpcode::ReadRemoteRpa),
        0x1C17 => Some(SleOpcode::ReadLocalRpa),
        0x1C18 => Some(SleOpcode::SetRpaEnable),
        0x1C19 => Some(SleOpcode::SetRpaTimeout),
        0x1C1A => Some(SleOpcode::ConfigSlbAuthPsk),
        0x1C1B => Some(SleOpcode::DeleteSlbAuthPsk),
        0x1C1C => Some(SleOpcode::ConfigSlbAuthPwd),
        0x1C1D => Some(SleOpcode::DeleteSlbAuthPwd),
        0x1C1E => Some(SleOpcode::ConfigSlbCipherAlgo),
        0x1C1F => Some(SleOpcode::ReadSlbCipherAlgo),
        0x1C20 => Some(SleOpcode::ConfigSlbSecAssoc),
        0x1C21 => Some(SleOpcode::ReadSlbSecAssoc),
        0x1C22 => Some(SleOpcode::ConfigSlbSecTimeout),
        0x1C23 => Some(SleOpcode::ReadSlbSecTimeout),
        0x2001 => Some(SleOpcode::ReadLocalMeasCap),
        0x2003 => Some(SleOpcode::SetMeasLinkParam),
        0x2005 => Some(SleOpcode::MeasAction),
        0x200B => Some(SleOpcode::EnableMeas),
        0x2401 => Some(SleOpcode::SlbCreateLogChannel),
        0x2402 => Some(SleOpcode::SlbUpdateLogChannel),
        0x2403 => Some(SleOpcode::SlbDeleteLogChannel),
        0x2801 => Some(SleOpcode::SyncUcastParam),
        0x2803 => Some(SleOpcode::SyncUcastCreate),
        0x2804 => Some(SleOpcode::SyncUcastRemove),
        0x2805 => Some(SleOpcode::SyncUcastAccept),
        0x2806 => Some(SleOpcode::SyncUcastReject),
        0x2807 => Some(SleOpcode::SyncMcastParam),
        0x2808 => Some(SleOpcode::SyncMcastInfo),
        0x2809 => Some(SleOpcode::SyncMcastCreate),
        0x280A => Some(SleOpcode::SyncMcastRemove),
        0x280B => Some(SleOpcode::SyncMcastAccept),
        0x280C => Some(SleOpcode::SyncMcastReject),
        0x280D => Some(SleOpcode::SyncDataPathConfig),
        0x280E => Some(SleOpcode::SyncDataPathRemove),
        0xF801 => Some(SleOpcode::TestModeEnable),
        0xF802 => Some(SleOpcode::TestRx),
        0xF803 => Some(SleOpcode::TestTx),
        0xF804 => Some(SleOpcode::TestRxResult),
        0xFC00 => Some(SleOpcode::VendorBase),
        _ => None,
    }
}

impl ControllerBackend {
    /// Only the owner's command worker uses this independently retained handle.
    /// Allocation/get is process-context, before releasing state; no I/O here.
    pub(crate) fn command_port(&self) -> Result<kernel::alloc::KBox<dyn super::sle_backend::CommandPort>> {
        use kernel::alloc::KBox;
        match self {
            Self::Native(c) => Ok(KBox::new(c.command_transport(), GFP_KERNEL)? as KBox<dyn super::sle_backend::CommandPort>),
        }
    }
    pub(crate) fn validate_command(&self, opcode: u16, params: &[u8]) -> Result {
        match self {
            Self::Native(c) => c.validate_command(opcode, params),
        }
    }

}

impl SleController for ControllerBackend {
    fn info(&self) -> SleControllerInfo {
        match self {
            Self::Native(c) => c.info(),
        }
    }

    fn close(&self) {
        match self {
            Self::Native(c) => c.close(),
        }
    }

}
