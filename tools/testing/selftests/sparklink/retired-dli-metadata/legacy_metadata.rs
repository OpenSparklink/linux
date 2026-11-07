// SPDX-License-Identifier: GPL-2.0
// Exact b35 metadata/catalog declarations, historical selftests only.
// ---------------------------------------------------------------------------
// DLI packet type indicators (T/XS 10003-2025 section 5.1)
// ---------------------------------------------------------------------------

/// DLI packet type byte on the transport layer.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DliPacketType {
    /// Host-to-controller command.
    Command = 0xA1,
    /// Controller-to-host event.
    Event = 0xA2,
    /// Asynchronous unicast data.
    AsyncUnicast = 0xA3,
    /// Synchronous unicast data.
    SyncUnicast = 0xA4,
    /// Asynchronous multicast data.
    AsyncMulticast = 0xA5,
}

// ---------------------------------------------------------------------------
// Controller capabilities
// ---------------------------------------------------------------------------

/// Transport bus type between the host and the SLE controller.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleBus {
    None = 0,
    Uart = 1,
    Spi = 2,
    Sdio = 3,
    Usb = 4,
    Mmio = 5,
    /// Explicit test provider; does not claim a physical transport or VirtualBackend.
    Test = 6,
}

/// Feature bits from the 10-byte (80-bit) feature set (T/XS 10003-2025 Table 9).
///
/// Stored as a bitmask in `SleControllerInfo::features`.
#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SleFeature {
    /// Bit 0: 加密
    Encryption = 1 << 0,
    /// Bit 1: 数据长度更新
    DataLenUpdate = 1 << 1,
    /// Bit 2: PING流程
    Ping = 1 << 2,
    /// Bit 3: 过滤策略
    FilterPolicy = 1 << 3,
    /// Bit 4: 隐私管理
    Privacy = 1 << 4,
    /// Bit 5: 无线帧类型2
    FrameType2 = 1 << 5,
    /// Bit 6: 无线帧类型3
    FrameType3 = 1 << 6,
    /// Bit 7: 无线帧类型4
    FrameType4 = 1 << 7,
    /// Bit 8: 2M带宽
    Bw2m = 1 << 8,
    /// Bit 9: 4M带宽
    Bw4m = 1 << 9,
    /// Bit 10: 导频密度4:1
    Pilot4to1 = 1 << 10,
    /// Bit 11: 导频密度8:1
    Pilot8to1 = 1 << 11,
    /// Bit 12: 导频密度16:1
    Pilot16to1 = 1 << 12,
    /// Bit 13: CRC32类型
    Crc32 = 1 << 13,
    /// Bit 14: MCS0
    Mcs0 = 1 << 14,
    /// Bit 15: MCS1
    Mcs1 = 1 << 15,
    /// Bit 16: MCS2
    Mcs2 = 1 << 16,
    /// Bit 17: MCS3
    Mcs3 = 1 << 17,
    /// Bit 18: MCS4
    Mcs4 = 1 << 18,
    /// Bit 19: MCS5
    Mcs5 = 1 << 19,
    /// Bit 20: MCS6
    Mcs6 = 1 << 20,
    /// Bit 21: MCS7
    Mcs7 = 1 << 21,
    /// Bit 22: MCS8
    Mcs8 = 1 << 22,
    /// Bit 23: MCS9
    Mcs9 = 1 << 23,
    /// Bit 24: MCS10
    Mcs10 = 1 << 24,
    /// Bit 25: MCS11
    Mcs11 = 1 << 25,
    /// Bit 26: MCS12
    Mcs12 = 1 << 26,
    /// Bit 27: 收发间隔25us
    TxRxGap25us = 1 << 27,
    /// Bit 28: 收发间隔50us
    TxRxGap50us = 1 << 28,
    /// Bit 29: 收发间隔75us
    TxRxGap75us = 1 << 29,
    /// Bit 30: 收发间隔100us
    TxRxGap100us = 1 << 30,
    /// Bit 31: 系统管理帧控制
    SysMgmtFrame = 1 << 31,
    /// Bit 32: 系统管理帧跳频算法
    SysMgmtHopping = 1 << 32,
    /// Bit 33: 最小可用信道流程
    MinAvailChannel = 1 << 33,
    /// Bit 34: 睡眠时钟精度更新
    SleepClkAccuracy = 1 << 34,
    /// Bit 35: 远程公钥验证
    RemotePkVerify = 1 << 35,
    /// Bit 36: 功率控制更新
    PowerControl = 1 << 36,
    /// Bit 37: 信道质量估计
    ChannelQuality = 1 << 37,
    /// Bit 38: 5GHz频段
    Band5ghz = 1 << 38,
    /// Bit 39: 角色切换
    RoleSwitch = 1 << 39,
    /// Bit 40: 异步数据组播-G节点
    AsyncDataMcastG = 1 << 40,
    /// Bit 41: 异步数据组播-T节点
    AsyncDataMcastT = 1 << 41,
    /// Bit 42: 异步双向组播-G节点
    AsyncBidiMcastG = 1 << 42,
    /// Bit 43: 异步双向组播-T节点
    AsyncBidiMcastT = 1 << 43,
    /// Bit 44: 异步反馈组播-G节点
    AsyncFbMcastG = 1 << 44,
    /// Bit 45: 异步反馈组播-T节点
    AsyncFbMcastT = 1 << 45,
    /// Bit 46: 异步链接态广播-G节点
    AsyncLinkBcastG = 1 << 46,
    /// Bit 47: 异步链接态广播-T节点
    AsyncLinkBcastT = 1 << 47,
    /// Bit 48: 同步数据组播-G节点
    SyncDataMcastG = 1 << 48,
    /// Bit 49: 同步数据组播-T节点
    SyncDataMcastT = 1 << 49,
    /// Bit 50: 同步双向组播-G节点
    SyncBidiMcastG = 1 << 50,
    /// Bit 51: 同步双向组播-T节点
    SyncBidiMcastT = 1 << 51,
    /// Bit 52: 同步反馈组播-G节点
    SyncFbMcastG = 1 << 52,
    /// Bit 53: 同步反馈组播-T节点
    SyncFbMcastT = 1 << 53,
    /// Bit 54: 同步链接态广播-G节点
    SyncLinkBcastG = 1 << 54,
    /// Bit 55: 同步链接态广播-T节点
    SyncLinkBcastT = 1 << 55,
    /// Bit 56: 异步单播链路参数更新
    AsyncUcastParamUpd = 1 << 56,
    /// Bit 57: 异步组播链路参数更新
    AsyncMcastParamUpd = 1 << 57,
    /// Bit 58: 同步链路参数更新
    SyncParamUpd = 1 << 58,
    /// Bit 59: 链接态广播链路参数更新
    LinkBcastParamUpd = 1 << 59,
    /// Bit 60: 先发后发TG模式
    TgMode = 1 << 60,
    /// Bit 61: 128比特NTP时间
    Ntp128 = 1 << 61,
    /// Bit 62: 64比特NTP时间
    Ntp64 = 1 << 62,
    /// Bit 63: 32比特NTP时间
    Ntp32 = 1u64 << 63,
}

/// Extended feature bits 64-72 (T/XS 10003-2025 Table 9, continued).
/// Stored in a separate `features_ext: u16` field.
pub const SLE_FEAT_EXT_CBG_FB_TYPE3: u16 = 1 << 0; // Bit 64
pub const SLE_FEAT_EXT_CBG_FB_TYPE4: u16 = 1 << 1; // Bit 65
pub const SLE_FEAT_EXT_NB_RANGING: u16 = 1 << 2; // Bit 66
pub const SLE_FEAT_EXT_UWB_RANGING: u16 = 1 << 3; // Bit 67
pub const SLE_FEAT_EXT_UWB_SENSING: u16 = 1 << 4; // Bit 68
pub const SLE_FEAT_EXT_NB_SENSING: u16 = 1 << 5; // Bit 69
pub const SLE_FEAT_EXT_SYNC_UCAST_G: u16 = 1 << 6; // Bit 70
pub const SLE_FEAT_EXT_SYNC_UCAST_T: u16 = 1 << 7; // Bit 71
pub const SLE_FEAT_EXT_VERIFY_BCAST: u16 = 1 << 8; // Bit 72

/// Static information about a controller.
pub struct SleControllerInfo {
    /// Human-readable name (e.g. "WS63-SLE").
    pub name: [u8; 32],
    /// Transport bus type.
    pub bus: SleBus,
    /// 6-byte SLE MAC address.
    pub addr: [u8; 6],
    /// Firmware version as a packed u32 (major.minor.patch).
    pub fw_version: u32,
    /// Bitmask of supported features (see [`SleFeature`]).
    pub features: u64,
    /// Extended feature bits 64-72 (see `SLE_FEAT_EXT_*`).
    pub features_ext: u16,
    /// Maximum PDU payload size in bytes.
    pub max_pdu_payload: u16,
    /// Queried connection limit; 0 means unknown/unavailable, never unlimited.
    pub max_connections: u8,
    /// Maximum MTU (SSAP message size) the controller supports.
    pub max_mtu: u16,
    /// Maximum payload segment size per single TX.
    pub max_mps: u16,
    /// Supported transport modes (bitmask, see `SLE_TRANSPORT_*`).
    pub transport_modes: u8,
    /// Measurement capabilities (bitmask, see `SLE_MEAS_*`).
    pub measurement_cap: u8,
    /// Security capabilities (bitmask, see `SLE_SEC_*`).
    pub security_cap: u16,
}

// Transport mode bitmask constants.
pub const SLE_TRANSPORT_UNRELIABLE: u8 = 1 << 0;
pub const SLE_TRANSPORT_RELIABLE: u8 = 1 << 1;
pub const SLE_TRANSPORT_FRAGMENTED: u8 = 1 << 2;

// Measurement capability bitmask constants.
pub const SLE_MEAS_RSSI: u8 = 1 << 0;
pub const SLE_MEAS_PATH_LOSS: u8 = 1 << 1;
pub const SLE_MEAS_POWER_MONITOR: u8 = 1 << 2;
pub const SLE_MEAS_CHANNEL_MAP: u8 = 1 << 3;

// Security capability bitmask constants.
pub const SLE_SEC_AES_CCM: u16 = 1 << 0;
pub const SLE_SEC_SM4: u16 = 1 << 1;
pub const SLE_SEC_OOB_AUTH: u16 = 1 << 2;
pub const SLE_SEC_ECDH_P256: u16 = 1 << 3;
pub const SLE_SEC_SC: u16 = 1 << 4;

impl Default for SleControllerInfo {
    fn default() -> Self {
        Self {
            name: [0u8; 32],
            bus: SleBus::None,
            addr: [0u8; 6],
            fw_version: 0,
            features: 0,
            features_ext: 0,
            max_pdu_payload: 0,
            max_connections: 0,
            max_mtu: 0,
            max_mps: 0,
            transport_modes: 0,
            measurement_cap: 0,
            security_cap: 0,
        }
    }
}

impl SleControllerInfo {
    /// Check whether a feature is supported.
    pub fn has_feature(&self, f: SleFeature) -> bool {
        self.features & (f as u64) != 0
    }
}

