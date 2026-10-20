//! Userspace loader and control plane for the XDP classifier.
//!
//! Responsibilities: compile-time embedding of the BPF object, attach to an
//! interface, translate CLI rules into LPM trie entries, drain the trace ring
//! buffer, and print counters. The datapath itself lives entirely in
//! `packet-tracer-ebpf`.

use std::{
    cmp::Reverse,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context as _, anyhow, bail};
use aya::{
    Ebpf,
    maps::{Array, LpmTrie, PerCpuArray, RingBuf, lpm_trie::Key},
    programs::{Xdp, XdpMode},
};
use clap::Parser;
use log::{info, warn};
use packet_tracer_common::{
    ACTION_DROP, ACTION_PASS, Config, Event, MAX_RULES_PER_PREFIX, PORT_ANY, PROTO_ANY, Rule,
    RuleSet, Stats,
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal, time,
};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

// --- CLI -------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "packet-tracer",
    about = "XDP source-prefix packet classifier",
    long_about = None,
)]
struct Opt {
    /// Interface to attach to.
    #[arg(short, long)]
    iface: String,

    /// Match rule, repeatable. Format: `<cidr>[,<proto>][,<port>]=<action>`
    ///
    /// Comma rather than colon as the field separator, because IPv6 literals
    /// are full of colons.
    ///
    /// Examples:
    ///   10.0.0.0/8=drop
    ///   192.168.1.5/32,tcp,22=drop
    ///   2001:db8::/32,udp=drop
    #[arg(short, long = "rule", verbatim_doc_comment)]
    rules: Vec<RuleSpec>,

    /// Attach mode. `driver` is true XDP in the NIC driver; `skb` is the
    /// generic fallback that runs after sk_buff allocation and works
    /// everywhere, including veth and most virtio NICs.
    #[arg(short, long, default_value = "driver")]
    mode: Mode,

    /// Emit a trace event for every packet, not just drops.
    #[arg(long)]
    trace_all: bool,

    /// Seconds between counter dumps. 0 disables.
    #[arg(long, default_value_t = 5)]
    stats_interval: u64,
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Driver,
    Skb,
    Hw,
}

impl FromStr for Mode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "driver" | "native" => Ok(Mode::Driver),
            "skb" | "generic" => Ok(Mode::Skb),
            "hw" | "offload" => Ok(Mode::Hw),
            other => Err(format!(
                "unknown mode `{other}` (expected driver, skb, or hw)"
            )),
        }
    }
}

impl From<Mode> for XdpMode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Driver => XdpMode::Driver,
            Mode::Skb => XdpMode::Skb,
            Mode::Hw => XdpMode::Hardware,
        }
    }
}

/// A rule as written on the command line, before it is split into an LPM key
/// and a [`Rule`] value.
#[derive(Debug, Clone)]
struct RuleSpec {
    addr: IpAddr,
    prefix_len: u32,
    proto: u8,
    port: u16,
    action: u8,
}

impl FromStr for RuleSpec {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (matcher, action) = s
            .rsplit_once('=')
            .ok_or_else(|| anyhow!("rule `{s}` has no `=<action>`"))?;

        let action = match action.trim() {
            "drop" | "deny" => ACTION_DROP,
            "pass" | "allow" => ACTION_PASS,
            other => bail!("unknown action `{other}` (expected drop or pass)"),
        };

        let mut fields = matcher.split(',');
        let cidr = fields
            .next()
            .ok_or_else(|| anyhow!("rule `{s}` is empty"))?
            .trim();

        let (addr, prefix_len) = parse_cidr(cidr)?;

        let mut proto = PROTO_ANY;
        let mut port = PORT_ANY;

        for field in fields {
            let field = field.trim();
            if field.is_empty() {
                continue;
            }
            // A field is a port if it parses as one, otherwise a protocol
            // name. Checked in that order so a numeric protocol is still
            // writable as a name.
            if let Ok(p) = field.parse::<u16>() {
                if p == 0 {
                    bail!("port 0 is the wildcard; omit the field instead");
                }
                port = p;
            } else {
                proto = match field.to_ascii_lowercase().as_str() {
                    "tcp" => IPPROTO_TCP,
                    "udp" => IPPROTO_UDP,
                    "icmp" => IPPROTO_ICMP,
                    "icmpv6" | "icmp6" => IPPROTO_ICMPV6,
                    other => bail!("unknown protocol `{other}`"),
                };
            }
        }

        if port != PORT_ANY && proto == PROTO_ANY {
            // The kernel program only reads ports for TCP and UDP, so a port
            // rule with no protocol could never match an ICMP packet anyway.
            // Rejecting it is clearer than silently never firing.
            bail!("rule `{s}` specifies a port but no protocol (tcp or udp)");
        }

        Ok(RuleSpec {
            addr,
            prefix_len,
            proto,
            port,
            action,
        })
    }
}

fn parse_cidr(s: &str) -> anyhow::Result<(IpAddr, u32)> {
    let (addr_str, len_str) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };

    let addr: IpAddr = addr_str
        .parse()
        .with_context(|| format!("`{addr_str}` is not an IP address"))?;

    let max_len = if addr.is_ipv6() { 128 } else { 32 };
    let prefix_len = match len_str {
        Some(l) => l
            .parse::<u32>()
            .with_context(|| format!("`{l}` is not a prefix length"))?,
        // A bare address is a host route.
        None => max_len,
    };

    if prefix_len > max_len {
        bail!("prefix /{prefix_len} is too long for {addr} (max /{max_len})");
    }

    Ok((addr, prefix_len))
}

// --- display ---------------------------------------------------------------

fn proto_name(p: u8) -> &'static str {
    match p {
        IPPROTO_ICMP => "icmp",
        IPPROTO_TCP => "tcp",
        IPPROTO_UDP => "udp",
        IPPROTO_ICMPV6 => "icmpv6",
        _ => "other",
    }
}

struct EventFmt<'a>(&'a Event);

impl fmt::Display for EventFmt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let e = self.0;
        let (src, dst): (IpAddr, IpAddr) = if e.is_ipv6 != 0 {
            (
                Ipv6Addr::from(e.src).into(),
                Ipv6Addr::from(e.dst).into(),
            )
        } else {
            let s: [u8; 4] = e.src[..4].try_into().unwrap();
            let d: [u8; 4] = e.dst[..4].try_into().unwrap();
            (Ipv4Addr::from(s).into(), Ipv4Addr::from(d).into())
        };

        let verdict = if e.action == ACTION_DROP { "DROP" } else { "PASS" };
        let proto = proto_name(e.proto);

        write!(f, "{verdict:4} {proto:6} ")?;
        if e.src_port != 0 || e.dst_port != 0 {
            write!(f, "{src}:{} -> {dst}:{}", e.src_port, e.dst_port)?;
        } else {
            write!(f, "{src} -> {dst}")?;
        }
        write!(f, " {} bytes", e.len)?;
        if e.vlan_depth > 0 {
            write!(f, " (vlan x{})", e.vlan_depth)?;
        }
        Ok(())
    }
}

/// Sum per-CPU counters into one total.
fn total_stats(map: &PerCpuArray<impl core::borrow::Borrow<aya::maps::MapData>, Stats>) -> anyhow::Result<Stats> {
    let per_cpu = map.get(&0, 0).context("reading stats map")?;
    let mut acc = Stats::default();
    for s in per_cpu.iter() {
        acc.total += s.total;
        acc.passed += s.passed;
        acc.dropped += s.dropped;
        acc.malformed += s.malformed;
        acc.ipv4 += s.ipv4;
        acc.ipv6 += s.ipv6;
        acc.non_ip += s.non_ip;
        acc.ringbuf_full += s.ringbuf_full;
    }
    Ok(acc)
}

// --- main ------------------------------------------------------------------

/// The BPF object, embedded at compile time.
///
/// `cargo xtask build-ebpf` must have run first; the path is the ebpf crate's
/// `target-dir` from its `.cargo/config`.
#[cfg(debug_assertions)]
const BPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!("../../target/bpfel-unknown-none/debug/packet-tracer");
#[cfg(not(debug_assertions))]
const BPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!("../../target/bpfel-unknown-none/release/packet-tracer");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    bump_memlock_rlimit();

    let mut bpf = Ebpf::load(BPF_OBJECT).context("loading BPF object")?;

    // --- populate rules before attaching ---------------------------------
    //
    // Deliberately ordered: the program starts seeing packets the instant it
    // attaches, and attaching with an empty trie would pass traffic that the
    // operator asked to be dropped. Small window, but it is the exact window
    // the tool exists to close.
    install_rules(&mut bpf, &opt.rules)?;

    {
        let mut config: Array<_, Config> = Array::try_from(
            bpf.map_mut("CONFIG").context("CONFIG map missing")?,
        )?;
        config.set(
            0,
            Config {
                trace_all: opt.trace_all as u8,
                _pad: [0; 7],
            },
            0,
        )?;
    }

    // --- attach ----------------------------------------------------------
    let program: &mut Xdp = bpf
        .program_mut("packet_tracer")
        .context("program `packet_tracer` missing from object")?
        .try_into()?;
    program.load().context("verifier rejected the program")?;

    let mode: XdpMode = opt.mode.into();
    program.attach(&opt.iface, mode).with_context(|| {
        format!(
            "attaching to {} in {:?} mode — if the driver lacks native XDP support, try --mode skb",
            opt.iface, opt.mode
        )
    })?;

    info!(
        "attached to {} ({:?} mode), {} rule(s) installed",
        opt.iface,
        opt.mode,
        opt.rules.len()
    );

    // --- drain the ring buffer -------------------------------------------
    let events = RingBuf::try_from(bpf.take_map("EVENTS").context("EVENTS map missing")?)?;

    // READABLE only: a BPF ring buffer is produced by the kernel and consumed
    // here, so registering for writability would arm an interest that can
    // never fire.
    //
    // SAFETY: `register_with_interest` requires that the fd stay open and
    // unchanged for the lifetime of the `AsyncFd`. `events` is moved in by
    // value, so the `RingBuf` — and the map fd it owns — outlives the
    // registration and is only closed when the `AsyncFd` is dropped. Nothing
    // else holds a copy of that fd.
    let mut events = unsafe { AsyncFd::register_with_interest(events, Interest::READABLE) }
        .map_err(std::io::Error::from)
        .context("registering ring buffer with the tokio reactor")?;

    let mut ticker = if opt.stats_interval > 0 {
        let mut t = time::interval(Duration::from_secs(opt.stats_interval));
        t.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        Some(t)
    } else {
        None
    };

    let stats_map: PerCpuArray<_, Stats> =
        PerCpuArray::try_from(bpf.map("STATS").context("STATS map missing")?)?;

    loop {
        tokio::select! {
            // Biased so that a saturated ring buffer cannot starve the
            // shutdown branch — without this, Ctrl-C under load is a coin flip.
            biased;

            _ = signal::ctrl_c() => {
                info!("detaching");
                break;
            }

            _ = async { ticker.as_mut().unwrap().tick().await }, if ticker.is_some() => {
                match total_stats(&stats_map) {
                    Ok(s) => info!(
                        "total={} pass={} drop={} malformed={} v4={} v6={} non-ip={} lost={}",
                        s.total, s.passed, s.dropped, s.malformed,
                        s.ipv4, s.ipv6, s.non_ip, s.ringbuf_full,
                    ),
                    Err(e) => warn!("stats read failed: {e}"),
                }
            }

            readable = events.readable_mut() => {
                let mut guard = readable.context("ring buffer poll failed")?;
                let ring = guard.get_inner_mut();
                while let Some(item) = ring.next() {
                    match parse_event(&item) {
                        Some(e) => println!("{}", EventFmt(&e)),
                        None => warn!("short ring buffer record: {} bytes", item.len()),
                    }
                }
                // Must clear readiness only after draining to empty, or epoll
                // will not re-arm and the consumer stalls with data pending.
                guard.clear_ready();
            }
        }
    }

    // Dropping `bpf` detaches the program and frees the maps.
    if let Ok(s) = total_stats(&stats_map) {
        info!(
            "final: total={} pass={} drop={} malformed={} lost={}",
            s.total, s.passed, s.dropped, s.malformed, s.ringbuf_full
        );
    }

    Ok(())
}

/// Reinterpret a ring buffer record as an [`Event`].
///
/// The kernel reserved exactly `size_of::<Event>()` bytes, but this is the
/// boundary where a mismatched `packet-tracer-common` between the two crates
/// would show up, so the length is checked rather than assumed.
fn parse_event(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < std::mem::size_of::<Event>() {
        return None;
    }
    // SAFETY: `Event` is `repr(C)`, is `Pod`, and the length is checked above.
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const Event) })
}

/// Does `outer/outer_len` contain `inner`? Both must be the same length.
///
/// Compares the first `outer_len` bits, most significant first — the same
/// order the kernel's LPM trie uses.
fn prefix_contains(outer: &[u8], outer_len: u32, inner: &[u8]) -> bool {
    debug_assert_eq!(outer.len(), inner.len());
    let full_bytes = (outer_len / 8) as usize;
    let rem_bits = (outer_len % 8) as u8;

    if outer[..full_bytes] != inner[..full_bytes] {
        return false;
    }
    if rem_bits == 0 {
        return true;
    }
    // Compare the leading `rem_bits` of the next byte. Shifting a u8 by 8 is
    // undefined, which is why the zero case returns above.
    let mask = 0xffu8 << (8 - rem_bits);
    outer[full_bytes] & mask == inner[full_bytes] & mask
}

/// Group rules by prefix and flatten overlaps into one [`RuleSet`] per prefix.
///
/// An LPM lookup returns only the longest matching prefix, so a `/32` entry
/// would hide every `/24` rule covering the same address. Each prefix
/// therefore inherits the rules of every shorter prefix containing it, ordered
/// longest-first, so that the datapath's first-match scan reproduces
/// most-specific-wins semantics with a single lookup.
///
/// `N` is the address width in bytes: 4 for IPv4, 16 for IPv6.
fn flatten<const N: usize>(
    specs: &[(&RuleSpec, [u8; N])],
) -> anyhow::Result<Vec<(u32, [u8; N], RuleSet)>> {
    // Distinct prefixes, preserving first-seen order so the output is stable.
    let mut prefixes: Vec<(u32, [u8; N])> = Vec::new();
    for (spec, octets) in specs {
        let p = (spec.prefix_len, *octets);
        if !prefixes.contains(&p) {
            prefixes.push(p);
        }
    }

    let mut out = Vec::with_capacity(prefixes.len());

    for &(prefix_len, octets) in &prefixes {
        // Every rule whose prefix contains this one, including this one.
        // Sorted by descending prefix length: most specific first.
        let mut applicable: Vec<&RuleSpec> = specs
            .iter()
            .filter(|(spec, other)| {
                spec.prefix_len <= prefix_len && prefix_contains(other, spec.prefix_len, &octets)
            })
            .map(|(spec, _)| *spec)
            .collect();

        // The sort is stable, so rules at equal specificity keep the order
        // they were given on the command line. That makes rule precedence
        // predictable rather than dependent on iteration order.
        applicable.sort_by_key(|s| Reverse(s.prefix_len));

        let mut set = RuleSet::empty();
        for spec in &applicable {
            if !set.push(Rule::new(spec.action, spec.proto, spec.port)) {
                bail!(
                    "too many rules apply to one prefix (limit {}); \
                     {} rules overlap here, including the ones inherited from \
                     shorter prefixes",
                    MAX_RULES_PER_PREFIX,
                    applicable.len()
                );
            }
        }

        out.push((prefix_len, octets, set));
    }

    Ok(out)
}

fn install_rules(bpf: &mut Ebpf, rules: &[RuleSpec]) -> anyhow::Result<()> {
    let v4: Vec<(&RuleSpec, [u8; 4])> = rules
        .iter()
        .filter_map(|r| match r.addr {
            // `octets()` is network byte order, which is what the trie wants —
            // see the matching note in the eBPF program.
            IpAddr::V4(a) => Some((r, a.octets())),
            IpAddr::V6(_) => None,
        })
        .collect();

    let v6: Vec<(&RuleSpec, [u8; 16])> = rules
        .iter()
        .filter_map(|r| match r.addr {
            IpAddr::V6(a) => Some((r, a.octets())),
            IpAddr::V4(_) => None,
        })
        .collect();

    {
        let mut trie: LpmTrie<_, [u8; 4], RuleSet> =
            LpmTrie::try_from(bpf.map_mut("RULES_V4").context("RULES_V4 map missing")?)?;
        for (prefix_len, octets, set) in flatten(&v4)? {
            trie.insert(&Key::new(prefix_len, octets), set, 0)
                .with_context(|| {
                    format!("inserting rules for {}/{}", Ipv4Addr::from(octets), prefix_len)
                })?;
        }
    }

    {
        let mut trie: LpmTrie<_, [u8; 16], RuleSet> =
            LpmTrie::try_from(bpf.map_mut("RULES_V6").context("RULES_V6 map missing")?)?;
        for (prefix_len, octets, set) in flatten(&v6)? {
            trie.insert(&Key::new(prefix_len, octets), set, 0)
                .with_context(|| {
                    format!("inserting rules for {}/{}", Ipv6Addr::from(octets), prefix_len)
                })?;
        }
    }

    Ok(())
}

/// Raise `RLIMIT_MEMLOCK`.
///
/// Only matters on kernels before 5.11, which charged BPF maps against the
/// locked-memory limit instead of the memory cgroup. Harmless after that, and
/// a failure here is not fatal — the map creation that follows will produce a
/// far better error message than anything we could write.
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `rlim` is a valid, fully initialized `rlimit`.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        log::debug!("could not raise RLIMIT_MEMLOCK; fine on kernels >= 5.11");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(s: &str) -> RuleSpec {
        s.parse().unwrap_or_else(|e| panic!("`{s}` should parse: {e}"))
    }

    #[test]
    fn bare_address_is_a_host_route() {
        let r = rule("10.1.2.3=drop");
        assert_eq!(r.prefix_len, 32);
        let r = rule("2001:db8::1=drop");
        assert_eq!(r.prefix_len, 128);
    }

    #[test]
    fn parses_prefix_and_action() {
        let r = rule("10.0.0.0/8=drop");
        assert_eq!(r.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(r.prefix_len, 8);
        assert_eq!(r.action, ACTION_DROP);
        assert_eq!(r.proto, PROTO_ANY);
        assert_eq!(r.port, PORT_ANY);

        assert_eq!(rule("10.0.0.0/8=pass").action, ACTION_PASS);
        assert_eq!(rule("10.0.0.0/8=allow").action, ACTION_PASS);
        assert_eq!(rule("10.0.0.0/8=deny").action, ACTION_DROP);
    }

    #[test]
    fn parses_proto_and_port_in_either_order() {
        let a = rule("192.168.1.5/32,tcp,22=drop");
        let b = rule("192.168.1.5/32,22,tcp=drop");
        assert_eq!((a.proto, a.port), (IPPROTO_TCP, 22));
        assert_eq!((b.proto, b.port), (IPPROTO_TCP, 22));
    }

    #[test]
    fn ipv6_literals_survive_the_comma_separator() {
        // The whole reason the separator is a comma and not a colon.
        let r = rule("2001:db8::/32,udp=drop");
        assert_eq!(r.addr, IpAddr::V6("2001:db8::".parse::<Ipv6Addr>().unwrap()));
        assert_eq!(r.prefix_len, 32);
        assert_eq!(r.proto, IPPROTO_UDP);
    }

    #[test]
    fn rejects_prefix_longer_than_family_allows() {
        assert!("10.0.0.0/33=drop".parse::<RuleSpec>().is_err());
        assert!("2001:db8::/129=drop".parse::<RuleSpec>().is_err());
        // /32 on v6 is a legitimate prefix, not an error.
        assert!("2001:db8::/32=drop".parse::<RuleSpec>().is_ok());
    }

    #[test]
    fn rejects_port_without_protocol() {
        // The datapath only reads ports for TCP and UDP, so this rule could
        // never fire; failing loudly beats silently never matching.
        assert!("10.0.0.0/8,22=drop".parse::<RuleSpec>().is_err());
    }

    #[test]
    fn rejects_malformed_rules() {
        assert!("10.0.0.0/8".parse::<RuleSpec>().is_err(), "no action");
        assert!("10.0.0.0/8=destroy".parse::<RuleSpec>().is_err(), "bad action");
        assert!("not-an-ip/8=drop".parse::<RuleSpec>().is_err(), "bad address");
        assert!("10.0.0.0/8,sctp=drop".parse::<RuleSpec>().is_err(), "bad proto");
        assert!("10.0.0.0/8,tcp,0=drop".parse::<RuleSpec>().is_err(), "port 0");
    }

    fn v4set(specs: &[RuleSpec]) -> Vec<(u32, [u8; 4], RuleSet)> {
        let pairs: Vec<_> = specs
            .iter()
            .map(|s| match s.addr {
                IpAddr::V4(a) => (s, a.octets()),
                IpAddr::V6(_) => panic!("v4 only"),
            })
            .collect();
        flatten(&pairs).expect("flatten should succeed")
    }

    #[test]
    fn prefix_containment() {
        let ten = [10, 0, 0, 0];
        assert!(prefix_contains(&ten, 8, &[10, 77, 0, 2]));
        assert!(!prefix_contains(&ten, 8, &[11, 0, 0, 1]));
        // /0 contains everything.
        assert!(prefix_contains(&[0, 0, 0, 0], 0, &[192, 168, 1, 1]));
        // Non-byte-aligned prefix: /12 of 10.16.0.0 covers 10.16..10.31.
        let p = [10, 16, 0, 0];
        assert!(prefix_contains(&p, 12, &[10, 16, 5, 5]));
        assert!(prefix_contains(&p, 12, &[10, 31, 255, 255]));
        assert!(!prefix_contains(&p, 12, &[10, 32, 0, 0]));
        // /32 is exact.
        assert!(prefix_contains(&[10, 0, 0, 1], 32, &[10, 0, 0, 1]));
        assert!(!prefix_contains(&[10, 0, 0, 1], 32, &[10, 0, 0, 2]));
    }

    #[test]
    fn specific_prefix_inherits_rules_from_broader_ones() {
        // This is the exact case that failed before rules were flattened: the
        // /32 ICMP rule used to shadow the /24 UDP rule, so UDP to 9999 was
        // passed when it should have been dropped.
        let specs = [
            rule("10.77.0.2/32,icmp=drop"),
            rule("10.77.0.0/24,udp,9999=drop"),
        ];
        let out = v4set(&specs);

        let (_, _, set) = out
            .iter()
            .find(|(len, oct, _)| *len == 32 && *oct == [10, 77, 0, 2])
            .expect("/32 prefix present");

        assert_eq!(set.len, 2, "/32 must inherit the /24 rule");
        // Most specific first.
        assert_eq!(set.rules[0].proto, IPPROTO_ICMP);
        assert_eq!(set.rules[1].proto, IPPROTO_UDP);
        assert_eq!(set.rules[1].port, 9999);

        // The /24 entry keeps only its own rule — nothing to inherit.
        let (_, _, broad) = out
            .iter()
            .find(|(len, _, _)| *len == 24)
            .expect("/24 prefix present");
        assert_eq!(broad.len, 1);
        assert_eq!(broad.rules[0].proto, IPPROTO_UDP);
    }

    #[test]
    fn non_overlapping_prefixes_do_not_inherit() {
        let specs = [
            rule("10.0.0.0/8,tcp,80=drop"),
            rule("192.168.0.0/16,tcp,80=drop"),
        ];
        for (_, _, set) in v4set(&specs) {
            assert_eq!(set.len, 1, "disjoint prefixes must stay independent");
        }
    }

    #[test]
    fn equal_specificity_keeps_command_line_order() {
        // Two rules on the same prefix: the earlier flag wins ties, so
        // precedence is what the operator wrote, not hash order.
        let specs = [
            rule("10.0.0.1/32,tcp,22=pass"),
            rule("10.0.0.1/32,tcp,22=drop"),
        ];
        let out = v4set(&specs);
        assert_eq!(out.len(), 1, "same prefix collapses to one entry");
        let (_, _, set) = &out[0];
        assert_eq!(set.len, 2);
        assert_eq!(set.rules[0].action, ACTION_PASS);
        assert_eq!(set.rules[1].action, ACTION_DROP);
    }

    #[test]
    fn overflowing_a_prefix_is_an_error_not_a_silent_truncation() {
        // Nine rules all covering 10.0.0.1 — one more than fits. Dropping the
        // ninth silently would mean quietly not enforcing a rule the operator
        // asked for.
        let mut specs = vec![rule("10.0.0.1/32,tcp,22=drop")];
        for i in 0..MAX_RULES_PER_PREFIX {
            specs.push(rule(&format!("10.0.0.0/8,tcp,{}=drop", 1000 + i)));
        }
        let pairs: Vec<_> = specs
            .iter()
            .map(|s| match s.addr {
                IpAddr::V4(a) => (s, a.octets()),
                IpAddr::V6(_) => unreachable!(),
            })
            .collect();
        assert!(flatten(&pairs).is_err());
    }

    #[test]
    fn ipv6_prefixes_flatten_too() {
        let specs = [
            rule("2001:db8::1/128,tcp,443=drop"),
            rule("2001:db8::/32,udp=drop"),
        ];
        let pairs: Vec<_> = specs
            .iter()
            .map(|s| match s.addr {
                IpAddr::V6(a) => (s, a.octets()),
                IpAddr::V4(_) => unreachable!(),
            })
            .collect();
        let out = flatten(&pairs).unwrap();
        let (_, _, set) = out.iter().find(|(len, _, _)| *len == 128).unwrap();
        assert_eq!(set.len, 2);
        assert_eq!(set.rules[0].port, 443);
        assert_eq!(set.rules[1].proto, IPPROTO_UDP);
    }

    #[test]
    fn event_layout_matches_the_kernel_side() {
        // If this changes, the ring buffer records written by the eBPF program
        // can no longer be read back correctly. The constants are written out
        // rather than computed so that a layout change fails the test instead
        // of silently agreeing with itself.
        //
        // 16 + 16 src/dst, three u16s, four u8s, two bytes of tail padding.
        // Alignment is 2, not 8, because the widest member is a u16 — which is
        // exactly why the read side uses `read_unaligned` rather than a plain
        // pointer deref.
        assert_eq!(std::mem::size_of::<Event>(), 44);
        assert_eq!(std::mem::align_of::<Event>(), 2);
        assert_eq!(std::mem::size_of::<Rule>(), 8);
        assert_eq!(std::mem::size_of::<Config>(), 8);
    }

    #[test]
    fn short_ring_buffer_records_are_rejected() {
        let short = vec![0u8; std::mem::size_of::<Event>() - 1];
        assert!(parse_event(&short).is_none());
        let exact = vec![0u8; std::mem::size_of::<Event>()];
        assert!(parse_event(&exact).is_some());
    }

    #[test]
    fn event_round_trips_through_bytes() {
        let e = Event {
            src: Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped().octets(),
            dst: [0; 16],
            src_port: 1234,
            dst_port: 22,
            len: 74,
            proto: IPPROTO_TCP,
            action: ACTION_DROP,
            is_ipv6: 0,
            vlan_depth: 1,
            _pad: [0; 2],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &e as *const Event as *const u8,
                std::mem::size_of::<Event>(),
            )
        };
        let back = parse_event(bytes).expect("round trip");
        assert_eq!(back.src_port, 1234);
        assert_eq!(back.dst_port, 22);
        assert_eq!(back.proto, IPPROTO_TCP);
        assert_eq!(back.vlan_depth, 1);
    }
}
