// SPDX-License-Identifier: GPL-2.0-only
// Runner inserts the exact production function body, not a verification copy.
// @@CONTROLLER_DATA@@

#[kani::proof]
#[kani::unwind(270)]
fn bounded_controller_data_schema() {
    let bytes: [u8; 265] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= bytes.len());
    let input = &bytes[..length];
    let accepted = native_controller_data_valid(input);
    if length < 5 || length > 260 {
        assert!(!accepted);
    } else {
        let handle = u16::from_le_bytes([bytes[0], bytes[1]]);
        assert_eq!(accepted, handle <= 0x0fff && bytes[4] as usize + 5 == length);
    }
}
