#![no_std]

#[derive(Copy, Clone)]
#[repr(C)]
pub struct PacketRule {
    pub drop: bool,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketRule {}
