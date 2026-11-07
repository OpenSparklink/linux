// SPDX-License-Identifier: GPL-2.0-only
// Actual unsupported controller methods with minimal dependency types.
extern crate self as kernel;
#[derive(Debug, PartialEq, Eq)]
pub struct Error(i32);
impl Error {
    pub fn from_errno(v: i32) -> Self {
        Self(v)
    }
}
pub mod bindings {
    pub const EOPNOTSUPP: u32 = 95;
}
pub mod prelude {
    pub use crate::Error;
    pub type Result<T = ()> = core::result::Result<T, Error>;
}
use prelude::*;
#[derive(Default)]
enum SleBus {
    #[default]
    None,
    Uart,
    Spi,
}
#[derive(Default)]
struct SleControllerInfo {
    name: [u8; 32],
    bus: SleBus,
    addr: [u8; 6],
    fw_version: u32,
    features: u64,
    features_ext: u64,
    max_pdu_payload: u16,
    max_connections: u16,
    max_mtu: u16,
    max_mps: u16,
    transport_modes: u8,
    measurement_cap: u8,
    security_cap: u8,
}
#[derive(Clone, Copy)]
enum SleOpcode {
    Reset,
    ReadLocalVersion,
}
trait SleController {
    fn info(&self) -> SleControllerInfo;
    fn open(&self) -> Result;
    fn send_command(&self, opcode: SleOpcode, params: &[u8]) -> Result;
    fn send_data(&self, handle: u16, data: &[u8]) -> Result;
    fn reset(&self) -> Result;
}
struct UartController {
    addr: [u8; 6],
}
struct SpiController {
    addr: [u8; 6],
}
impl SleController for UartController {
    // @@UART_METHODS@@
}
impl SleController for SpiController {
    // @@SPI_METHODS@@
}
fn rejected(c: &dyn SleController) {
    assert_eq!(c.open(), Err(Error(-95)));
    for opcode in [SleOpcode::Reset, SleOpcode::ReadLocalVersion] {
        for size in [0, 1, 255, 256, 4096] {
            assert_eq!(c.send_command(opcode, &vec![0; size]), Err(Error(-95)));
            for handle in [0, 1, 65535] {
                assert_eq!(c.send_data(handle, &vec![0; size]), Err(Error(-95)));
            }
        }
    }
    assert_eq!(c.reset(), Err(Error(-95)));
    let i = c.info();
    assert_eq!(i.fw_version, 0);
    assert_eq!(i.features | i.features_ext, 0);
    assert_eq!(
        (i.max_pdu_payload, i.max_connections, i.max_mtu, i.max_mps),
        (0, 0, 0, 0)
    );
    assert_eq!(i.transport_modes | i.measurement_cap | i.security_cap, 0);
    assert_eq!(i.addr, [1; 6]);
    assert!(i.name.starts_with(b"sparklink-"));
    assert!(matches!(i.bus, SleBus::Uart | SleBus::Spi));
}
#[test]
fn uart_never_reports_hardware_success_or_capabilities() {
    rejected(&UartController { addr: [1; 6] });
}
#[test]
fn spi_never_reports_hardware_success_or_capabilities() {
    rejected(&SpiController { addr: [1; 6] });
}
