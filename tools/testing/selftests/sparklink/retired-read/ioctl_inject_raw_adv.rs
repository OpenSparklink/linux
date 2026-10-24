fn ioctl_inject_raw_adv(context: &RuntimeContext, arg: usize) -> Result<isize> {
    let inject: SleInjectRawAdv = read_user_struct(arg)?;
    let len = inject.pdu_len as usize;
    if !(6..=264).contains(&len) {
        return Err(EINVAL);
    }
    let pdu = sle_pdu::AdvPdu::deserialize(&inject.pdu_data[..len]).ok_or(EINVAL)?;
    {
        let mut ss = context.lock()?;
        let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
        s.adv_scan.process_adv_pdu(&pdu, inject.rssi)?;
    }
    Ok(0)
}
