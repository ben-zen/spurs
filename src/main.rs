// SPDX-FileCopyrightText: Copyright Ben Lewis, 2026.
// SPDX-License-Identifier: Artistic-2.0

pub mod dhcp;
pub mod option;

use crate::option::SubnetMask;

fn main() {
    println!("Hello, world!");
    let mask = SubnetMask::new([255, 255, 255, 0]);
    println!("a subnet mask takes up {} bytes and looks like {:?}", size_of::<SubnetMask>(), mask);
}
