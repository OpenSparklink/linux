pub(crate) fn process_controller_event(shared: &mut ControllerState, ev: &sle_dli::SleEvent) {
    // Credits are an absolute controller advertisement, not an increment.
    // A successful CommandStatus accepts asynchronous work; it does not finish it.
    // USB raw results are resolved by the Host's captured sequence, below.
    // Unmatched or internal USB responses must never consume a raw entry.
    if !shared.controller.uses_command_host() {
        match ev {
            sle_dli::SleEvent::CommandCredits { credits } => shared.command_credits = *credits,
            sle_dli::SleEvent::CommandComplete {
                opcode,
                command_credits,
                status,
                data,
            } => {
                shared.command_credits = *command_credits;
                shared
                    .cmd_pending
                    .resolve(*opcode as u16, *status as u8, data.as_slice());
            }
            sle_dli::SleEvent::CommandStatus {
                opcode,
                command_credits,
                status,
            } => {
                shared.command_credits = *command_credits;
                if *status != sle_dli::SleStatus::Success {
                    shared
                        .cmd_pending
                        .resolve(*opcode as u16, *status as u8, &[]);
                }
            }
            _ => {}
        }
    }

    // Native Host/Session own physical/data state. Legacy controller-global
    // security/RPA and automatic pairing responders are not production paths.

}
impl WorkItem<1> for ControllerRuntime {
    type Pointer = Arc<ControllerRuntime>;

    fn run(this: Arc<ControllerRuntime>) {
        if *this.schedule_gate.lock() {
            return;
        }
        let more = {
            let mut guard = this.state.lock();
            let Some(runtime) = Option::as_mut(&mut *guard) else {
                return;
            };
            if runtime.controller.uses_command_host() {
                let request = this.host.lock().next(|seq| {
                    runtime
                        .cmd_pending
                        .find_by_seq(seq)
                        .is_some_and(|entry| entry.is_pending() && !entry.is_expired())
                });
                let request = match request {
                    Ok(request) => request,
                    Err(error) => { fail_host(&this, runtime, error); return; }
                };
                if let Some(request) = request {
                    let transport = match runtime.controller.command_port() {
                        Ok(port) => port,
                        Err(error) => { fail_host(&this, runtime, error); return; }
                    };
                    // All providers retain their own resources. Runtime/Host/
                    // IRQ state never spans a blocking USB transfer or join.
                    drop(guard);
                    match transport.submit(request.opcode,
                        &request.params[..request.param_len as usize], request.recipe, request.connection) {
                        Ok(()) => {
                            if this.host.lock().transport_complete(request.cookie) { this.schedule_rx(0); }
                        }
                        Err(error) => {
                            let mut guard = this.state.lock();
                            if let Some(runtime) = Option::as_mut(&mut *guard) { fail_host(&this, runtime, error); }
                        }
                    }
                    return;
                }
                // Reply consumption, not bulk acceptance, releases this slot.
                return;
            }
            for _ in 0..8 {
                if runtime.command_credits == 0 {
                    break;
                }
                let Some(req) = runtime.cmd_queue.pop() else {
                    break;
                };
                let plen = req.param_len as usize;
                runtime.command_credits -= 1;
                if runtime
                    .controller
                    .send_command_raw(req.opcode, &req.params[..plen])
                    .is_err()
                {
                    runtime.cmd_pending.resolve_seq(req.seq, 0x03, &[]);
                }
            }
            runtime.command_credits > 0 && !runtime.cmd_queue.is_empty()
        };
        if more {
            this.kick_commands();
        }
    }
}
