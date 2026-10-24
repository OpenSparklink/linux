# Retired transport models

Exact UART/SPI sources from kernel bf8663bb78eb are retained here as historical
experimental models, outside the production module graph. Unsupported hardware
methods remain covered by `run_backend_containment.py`; this does not qualify
transport hardware or the historical SPI framing scheme.

Immediate removal: configfs-constructed None/Uart/Spi backend dispatch,
ignored-open-error device registration, and the global selector's successful
claims to choose those buses. Module init now leaves an empty registry. Only
successful bus-driver registration may create a Runtime.

Moved to tests: unsupported UART/SPI controller objects and unused UART encoder
and SPI framing/model source. Existing hardware rejection tests use these same
archived method bodies; no production fake Complete or success fallback.

Retained pending replacement: UART receive framing used by serdev; actual
USB/serdev/WS73 selectors and bus callbacks. A registered Backend descriptor,
per-device parser, references/module ownership, generation and stop/callback
barriers must replace these remaining selectors before WP13 is complete.

The unpublished selector still reports none, accepts none/0, rejects uart/spi/
usb selections with EOPNOTSUPP and invalid names with EINVAL. It cannot select
an attached device; use the per-registration controller API. No compatibility
period or real UART/SPI support is claimed. Kernel K#4/#9/#10/#19 and U#1/#6/#8
remain open; clean module/VM plus exact real WS73 RF/data regression are gates.

Follow-up: the sole serdev consumer proved unconnected at Kab9e5ec; its skeleton
and decoder now reside in selftests. No UART/parser is linked by the production
core; a proper registered provider must reconnect an appropriate per-device
framer through the Backend seam. Historical claims above retain their batch
baseline, not current production support.
