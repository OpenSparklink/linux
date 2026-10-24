// SPDX-License-Identifier: GPL-2.0-only
fn ioctl_legacy_dli_poll(context: &RuntimeContext, arg: usize) -> Result<isize> {
    let mut guard = context.lock()?;
    let state = Option::as_mut(&mut *guard).ok_or(ENODEV)?;
    let event = match state.peek_dli_event() {
        Some(event) => event,
        None => {
            let event = state.controller.poll_event().ok_or(EAGAIN)?;
            let wire = sle_dli_event_to_wire(&event);
            state.push_dli_event(wire);
            wire
        }
    };
    write_user_struct(arg, &event)?;
    let _ = state.pop_dli_event();
    Ok(0)
}
