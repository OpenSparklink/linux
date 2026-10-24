# Unconnected serdev skeleton

Exact sources from Kab9e5ecdf048 are retained here for historical regression
and reference. No serdev_device_driver/probe/remove registration calls this
skeleton; sle_serdev_alloc/rust_ctx are not connected to a real bus entry point.
The ignored callback ctx/global parser, GFP_KERNEL receive allocations,
nonatomic command table and init-failure fallback must not enter production.

Immediate removal: net module/C FFI linkage, parser init, dormant Serdev
selector/factory/activation, and unprovided H4/SPI builtin descriptors.
Moved to tests: this full skeleton and the prior decoder at
../retired-transport/uart_decoder.rs. Historical metadata/decoder and rejection
regressions use the same source; no wire Engine or real transport qualification.

Waiting for replacement: new drivers/sparklink serdev provider of the common
Backend API, descriptor/start/submit/stop/RX/fault, per-registration parser,
independent bounded ingress, no sleep/alloc in atomic callbacks, generation
validation, module references and stop/drain before freeing ctx. Reconnect only
with an actual registered caller and tests for two interleaved devices,
partial init/late callbacks/removal and actual standard framing. Full WP13 and
K#4/#9/#10/#12/#19 remain open. WS73 USB/runtime/data paths are retained.
