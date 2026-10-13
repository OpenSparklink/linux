extern crate self as kernel;
pub mod prelude { pub type Result<T=()> = std::result::Result<T,i32>; pub const EINVAL:i32=22; pub const EBUSY:i32=16; }
#[path="sle_power.rs"]
mod power;
#[test] fn interval_limits_and_supervision_relation() {
    let mut p=power::ConnInterval::default(); assert!(p.validate().is_ok());
    for n in [0,5,3201,u16::MAX] { p.min_interval=n; assert!(p.validate().is_err()); }
    let p=power::ConnInterval {min_interval:6,max_interval:3200,current_interval:6,latency:4,supervision_timeout:10};assert!(p.validate().is_err());
}
#[test] fn force_active_blocks_suspend_and_releases() {
    let mut p=power::PowerInner::new();p.force_active(true);assert_eq!(p.suspend(),Err(16));p.force_active(false);assert!(p.suspend().is_ok());p.resume();assert_eq!(p.state,power::PowerState::Active);
}
#[test] fn idle_and_activity_are_only_a_historical_model() {
    let mut p=power::PowerInner::new();assert!(p.set_mode(2));assert_eq!(p.state,power::PowerState::Idle);p.on_activity();assert_eq!(p.state,power::PowerState::Active);assert_eq!(p.stats.transitions,2);
}
