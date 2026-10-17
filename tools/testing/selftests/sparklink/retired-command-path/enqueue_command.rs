// SPDX-License-Identifier: GPL-2.0-only
// Exact retired K64 command-admission body; historical test only.
pub(crate) fn enqueue_command(
    owner: &kernel::sync::Arc<super::ControllerRuntime>, opcode: u16, params: &[u8],
    intent: Option<super::sle_command_plan::DiscoveryIntent>,
) -> Result {
    use super::sle_command_plan::RecipePart;
    let mut host = owner.host.lock();
    let gate = owner.schedule_gate.lock();
    if *gate { return Err(ENODEV); }
    let result = if let Some(intent) = intent {
        host.enqueue_recipe(intent, &[RecipePart { opcode, params }])
    } else { host.enqueue(opcode, params, 0) };
    drop(gate); drop(host);
    result?;
    owner.kick_commands();
    Ok(())
}
