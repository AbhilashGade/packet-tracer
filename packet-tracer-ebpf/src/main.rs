#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use packet_tracer_common::PacketRule;

#[map]
static mut RULES: HashMap<u32, PacketRule> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn packet_tracer(ctx: XdpContext) -> u32 {
    match try_packet_tracer(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_packet_tracer(ctx: XdpContext) -> Result<u32, u32> {
    let ip = ctx.ip()?;

    if let Some(rule) = unsafe { RULES.get(&ip.saddr.into()) } {
        if rule.drop {
            info!(&ctx, "dropping packet from {}", ip.saddr);
            return Ok(xdp_action::XDP_DROP);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
