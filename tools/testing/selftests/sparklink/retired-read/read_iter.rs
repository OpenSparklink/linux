    fn read_iter(kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterDest<'_>) -> Result<usize> {
        let me = kiocb.file();
        // Sync broadcast events into per-fd queue before reading.
        Self::sync_broadcast(me.as_ref());
        let mut guard = me.events.lock();
        guard.copy_records(iov.len(), |bytes| iov.copy_to_iter(bytes))
    }
