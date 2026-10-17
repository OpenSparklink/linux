// SPDX-License-Identifier: GPL-2.0-only
// Extracted production bodies; kernel, firmware, FFI and registry dependencies only.
extern crate self as kernel;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Mutex,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(i32);
impl Error {
    fn from_errno(n: i32) -> Self {
        Self(n)
    }
    fn to_errno(self) -> i32 {
        self.0
    }
}
const ENOENT: Error = Error(-2);
const EIO: Error = Error(-5);
const EINVAL: Error = Error(-22);
const EFBIG: Error = Error(-27);
const ENODEV: Error = Error(-19);
const EPROTO: Error = Error(-71);
type Result<T = ()> = std::result::Result<T, Error>;
#[macro_export]
macro_rules! pr_info { ($($v:tt)*) => { { let _ = format_args!($($v)*); } } }
#[macro_export]
macro_rules! pr_err { ($($v:tt)*) => { { let _ = format_args!($($v)*); } } }
#[macro_export]
macro_rules! pr_warn { ($($v:tt)*) => { { let _ = format_args!($($v)*); } } }
#[macro_export]
macro_rules! pr_debug { ($($v:tt)*) => { { let _ = format_args!($($v)*); } } }
#[macro_export]
macro_rules! c_str {
    ($s:literal) => {
        std::ffi::CStr::from_bytes_with_nul(concat!($s, "\0").as_bytes()).unwrap()
    };
}
pub mod bindings {
    pub const EPROTO: u32 = 71;
}
pub mod str {
    pub use std::ffi::CStr;
}
pub mod device {
    pub struct Core;
    pub struct Device<T = Core>(pub std::marker::PhantomData<T>);
}
pub mod usb {
    use super::device;
    pub struct Interface<T> {
        pub dev: device::Device<T>,
    }
    impl<T> AsRef<device::Device<T>> for Interface<T> {
        fn as_ref(&self) -> &device::Device<T> {
            &self.dev
        }
    }
}
struct State {
    request_error: Option<Error>,
    size: usize,
    download_ret: i32,
    init_rets: [i32; 2],
    init_calls: usize,
    mac_ret: i32,
    mac: [u8; 6],
    reg_ret: i32,
    switch_error: Option<Error>,
    events: Vec<&'static str>,
    published: Option<([u8; 6], u32, u8)>,
    download_calls: usize,
}
static STATE: Mutex<Option<State>> = Mutex::new(None);
static USB_DEV_COUNT: AtomicU32 = AtomicU32::new(0);
fn state<T>(f: impl FnOnce(&mut State) -> T) -> T {
    f(STATE.lock().unwrap().as_mut().unwrap())
}
fn reset() {
    USB_DEV_COUNT.store(0, Ordering::Relaxed);
    *STATE.lock().unwrap() = Some(State {
        request_error: Some(ENOENT),
        size: 16,
        download_ret: 0,
        init_rets: [0; 2],
        init_calls: 0,
        mac_ret: 0,
        mac: [1, 2, 3, 4, 5, 6],
        reg_ret: 0,
        switch_error: None,
        events: vec![],
        published: None,
        download_calls: 0,
    });
}
struct Firmware(Vec<u8>);
impl Firmware {
    fn request(name: &str::CStr, _dev: &device::Device) -> Result<Self> {
        assert_eq!(name.to_bytes(), b"sparklink/sle_usb_v1.bin");
        state(|s| {
            s.events.push("request");
            s.request_error
                .map_or_else(|| Ok(Self(vec![0x69; s.size])), Err)
        })
    }
    fn size(&self) -> usize {
        self.0.len()
    }
    fn data(&self) -> &[u8] {
        &self.0
    }
}
unsafe fn sle_usb_dev_download_fw(id: i32, data: *const u8, size: i32, chunk: i32) -> i32 {
    assert_eq!((id, chunk), (7, 0));
    assert!(size > 0);
    assert!(unsafe { std::slice::from_raw_parts(data, size as usize) }
        .iter()
        .all(|x| *x == 0x69));
    state(|s| {
        s.events.push("download");
        s.download_calls += 1;
        s.download_ret
    })
}
unsafe fn sle_usb_dev_init_controller(id: i32) -> i32 {
    assert_eq!(id, 7);
    state(|s| {
        s.events.push("init");
        let n = s.init_calls;
        s.init_calls += 1;
        s.init_rets[n]
    })
}
unsafe fn sle_usb_dev_get_mac(id: i32, mac: *mut u8) -> i32 {
    assert_eq!(id, 7);
    state(|s| {
        s.events.push("mac");
        let fresh = if s.init_calls == 2 {
            [6, 5, 4, 3, 2, 1]
        } else {
            s.mac
        };
        unsafe { std::ptr::copy_nonoverlapping(fresh.as_ptr(), mac, 6) };
        s.mac_ret
    })
}
unsafe fn sle_usb_dev_get_fw_version(id: i32) -> u32 {
    assert_eq!(id, 7);
    state(|s| {
        s.events.push("version");
        s.init_calls as u32
    })
}
unsafe fn sle_usb_dev_get_command_credits(id: i32) -> u8 {
    assert_eq!(id, 7);
    state(|s| s.events.push("credits"));
    3
}
#[derive(Clone,Debug)]
pub struct UsbDevice;
impl UsbDevice {
 fn as_raw(&self)->i32{7}
 fn create(identity:DeviceIdentity,ptr:*mut core::ffi::c_void)->Result<Self>{
  assert_eq!(identity,DeviceIdentity{id:7,generation:42});assert!(!ptr.is_null());
  let r=state(|s|{s.events.push("register");s.reg_ret});if r!=0{Err(if r<0{Error(r)}else{EIO})}else{Ok(Self)}
 }
 fn retire(&self){state(|s|s.events.push("join"));}
}
mod sle_usb{pub use super::UsbDevice;}
struct UsbBinding{identity:DeviceIdentity,device:UsbDevice}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct DeviceIdentity {id:u16,generation:u64}
fn reserve_usb_identity()->Result<DeviceIdentity>{
 state(|s|s.events.push("attach"));Ok(DeviceIdentity{id:7,generation:42})
}
fn sle_switch_controller_usb(identity: DeviceIdentity, _device:UsbDevice, addr: [u8; 6], version: u32, credits: u8) -> Result {
    assert_eq!(identity, DeviceIdentity{id:7,generation:42});
    state(|s| {
        s.events.push("publish");
        if let Some(e) = s.switch_error {
            return Err(e);
        }
        s.published = Some((addr, version, credits));
        Ok(())
    })
}
fn sle_quiesce_device(identity: DeviceIdentity) {
    assert_eq!(identity,DeviceIdentity{id:7,generation:42});
    state(|s| s.events.push("quiesce"));
}
fn sle_detach_device(identity: DeviceIdentity) {
    assert_eq!(identity,DeviceIdentity{id:7,generation:42});
    state(|s| s.events.push("detach"));
}
mod sle_fw {
    use super::*;
    // @@LOADER@@
}
mod production {
    use super::*;
    // @@PREPARE@@
    pub fn probe() -> Result<DeviceIdentity> {
        let binding=probe_usb_device(&usb::Interface {
            dev: device::Device(std::marker::PhantomData),
        })?;
        assert_eq!(binding.device.as_raw(),7);Ok(binding.identity)
    }
}
fn failed(expected: Error) {
    assert_eq!(production::probe(), Err(expected));
    state(|s| {
        if s.reg_ret==0 {
            assert_eq!(&s.events[s.events.len()-3..], &["quiesce","join","detach"]);
        } else {
            assert_eq!(&s.events[s.events.len()-2..], &["quiesce","detach"]);
            assert!(!s.events.contains(&"join"),"must not unregister another C table owner");
        }
        assert!(s.published.is_none());
    });
    assert_eq!(USB_DEV_COUNT.load(Ordering::Relaxed), 0);
}
#[test]
fn absent_is_the_only_optional_request_error() {
    reset();
    assert_eq!(production::probe(), Ok(DeviceIdentity{id:7,generation:42}));
    state(|s| {
        assert_eq!(
            s.events,
            ["attach", "register", "init", "request", "mac", "version", "credits", "publish"]
        );
        assert_eq!(s.published, Some(([1, 2, 3, 4, 5, 6], 1, 3)));
    });
    assert_eq!(USB_DEV_COUNT.load(Ordering::Relaxed), 1);
}
#[test]
fn upload_requeries_and_publishes_fresh_identity() {
    reset();
    state(|s| s.request_error = None);
    assert_eq!(production::probe(), Ok(DeviceIdentity{id:7,generation:42}));
    state(|s| {
        assert_eq!(
            s.events,
            [
                "attach", "register", "init", "request", "download", "init", "mac", "version",
                "credits", "publish"
            ]
        );
        assert_eq!(s.published, Some(([6, 5, 4, 3, 2, 1], 2, 3)));
    });
}
#[test]
fn request_errors_never_skip_the_load() {
    for e in [Error(-13), EIO, EINVAL, EFBIG, Error(-12)] {
        reset();
        state(|s| s.request_error = Some(e));
        failed(e);
        state(|s| assert_eq!(s.download_calls, 0));
    }
}
#[test]
fn all_negative_download_errors_remain_errors() {
    for e in [-5, -19, -71, -121, -110] {
        reset();
        state(|s| {
            s.request_error = None;
            s.download_ret = e;
        });
        failed(Error(e));
        state(|s| assert_eq!(s.init_calls, 1));
    }
}
#[test]
fn unexpected_positive_download_does_not_publish() {
    reset();
    state(|s| {
        s.request_error = None;
        s.download_ret = 1;
    });
    failed(EIO);
}
#[test]
fn bootstrap_requires_exact_zero_both_times() {
    for e in [-19, -71, -121, 1] {
        reset();
        state(|s| s.init_rets[0] = e);
        failed(if e < 0 { Error(e) } else { EIO });
        state(|s| assert!(!s.events.contains(&"request")));
        reset();
        state(|s| {
            s.request_error = None;
            s.init_rets[1] = e;
        });
        failed(if e < 0 { Error(e) } else { EIO });
        state(|s| assert!(!s.events.contains(&"mac")));
    }
}
#[test]
fn invalid_identity_cannot_publish_placeholder() {
    for mac in [[0; 6], [0xff; 6]] {
        reset();
        state(|s| s.mac = mac);
        failed(EPROTO);
        state(|s| assert!(!s.events.contains(&"version")));
    }
}
#[test]
fn metadata_errno_and_positive_anomaly_fail_closed() {
    for ret in [-19, 1] {
        reset();
        state(|s| s.mac_ret = ret);
        failed(if ret < 0 { Error(ret) } else { EIO });
    }
}
#[test]
fn register_failure_does_not_bootstrap() {
    for ret in [-19, 1] {
        reset();
        state(|s| s.reg_ret = ret);
        failed(if ret < 0 { Error(ret) } else { EIO });
        state(|s| assert!(!s.events.contains(&"init")));
    }
}
#[test]
fn firmware_size_limits_precede_ffi() {
    for (size, e) in [(0, EINVAL), (4 * 1024 * 1024 + 1, EFBIG)] {
        reset();
        state(|s| {
            s.request_error = None;
            s.size = size;
        });
        failed(e);
        state(|s| assert_eq!(s.download_calls, 0));
    }
}
#[test]
fn maximum_firmware_is_borrowed_synchronously() {
    reset();
    state(|s| {
        s.request_error = None;
        s.size = 4 * 1024 * 1024;
    });
    assert_eq!(production::probe(), Ok(DeviceIdentity{id:7,generation:42}));
    state(|s| assert_eq!(s.download_calls, 1));
}
#[test]
fn publish_failure_keeps_index_reserved_until_join() {
    reset();
    state(|s| s.switch_error = Some(ENODEV));
    failed(ENODEV);
    state(|s| {
        assert_eq!(
            &s.events[s.events.len() - 4..],
            ["publish", "quiesce", "join", "detach"]
        )
    });
}
