// Retired transport-specific Core wrappers, history only.
pub(crate) fn reserve_usb_identity() -> Result<sle_dev::DeviceIdentity> {
    let mut info = sle_dli::SleControllerInfo::default();
    let name = b"sparklink-usb";
    info.name[..name.len()].copy_from_slice(name);
    info.bus = sle_dli::SleBus::Usb;
    reserve_backend_identity(&info)
}
pub(crate) fn sle_suspend_device(identity: sle_dev::DeviceIdentity) {
    if let Some(owner) = runtime_by_id(identity.id).filter(|owner| owner.identity == identity) {
        if let Some(state) = Option::as_mut(&mut *owner.state.lock()) { let _ = state.power.suspend(); }
    }
}
pub(crate) fn sle_resume_device(identity: sle_dev::DeviceIdentity) {
    if let Some(owner) = runtime_by_id(identity.id).filter(|owner| owner.identity == identity) {
        if let Some(state) = Option::as_mut(&mut *owner.state.lock()) { state.power.resume(); }
    }
}
pub(crate) fn runtime_by_id(id: u16) -> Option<Arc<ControllerRuntime>> {
    SUBSYSTEM.lock().as_ref().and_then(|s| s.runtime(id))
}
pub(crate) fn sle_quiesce_device(identity: sle_dev::DeviceIdentity) {
    if let Some(owner) = runtime_by_id(identity.id).filter(|owner| owner.identity == identity) { owner.invalidate(); }
}
pub(crate) fn reserve_backend_identity(info: &sle_dli::SleControllerInfo) -> Result<sle_dev::DeviceIdentity> {
    reserve_backend_identity_profile(info, 0)
}
