fn ioctl_inject_adv(context: &RuntimeContext, me: Pin<&SparkLinkCtl>, arg: usize) -> Result<isize> {
    let inject: SleInjectAdv = read_user_struct(arg)?;
    let mut builder = sle_pdu::AdvDataBuilder::new();
    let _ = builder.push_discovery_level(inject.discovery_level);
    let _ = builder.push_sle_addr(&inject.addr);
    let name_len = (inject.name_len as usize).min(ADV_NAME_MAX);
    if name_len > 0 {
        let _ = builder.push_complete_name(&inject.name[..name_len]);
    }
    let pdu = sle_pdu::AdvPdu::build(
        sle_pdu::BroadcastType::AccessibleScannable,
        sle_pdu::PacketType::BasicAdv,
        0,
        &builder,
    );
    {
        let mut ss = context.lock()?;
        let s = Option::as_mut(&mut *ss).ok_or(ENODEV)?;
        s.adv_scan.process_adv_pdu(&pdu, inject.rssi)?;
    }
    let name_len = (inject.name_len as usize).min(31);
    SparkLinkCtl::broadcast_event(
                context,
        me.as_ref(),
        sle_event::SleWireEvent::adv_report(
            inject.addr,
            inject.rssi,
            inject.discovery_level,
            &inject.name[..name_len],
        ),
    )?;
    genl_bridge::notify_event(0x02, 0, &inject.addr);
    dev_info!(
        me.dev,
        "sparklink: injected ADV from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} rssi={}\n",
        inject.addr[0],
        inject.addr[1],
        inject.addr[2],
        inject.addr[3],
        inject.addr[4],
        inject.addr[5],
        inject.rssi
    );
    Ok(0)
}
