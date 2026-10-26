//! Single-connection platform capability. Static pages remain pinned even when
//! revocation is refused. No peer-controlled pointer ever becomes a Rust reference.
use core::sync::atomic::AtomicBool;

use hermit_sync::InterruptTicketMutex;
use xen::grant::{ForeignMapping, GrantTable};

use super::*;

static mut TABLE: SharedInfoPage = SharedInfoPage([0; 4096]);
static mut TX: SharedInfoPage = SharedInfoPage([0; 4096]);
static mut RX: SharedInfoPage = SharedInfoPage([0; 4096]);
static CLAIMED: AtomicBool = AtomicBool::new(false);
struct Connection {
	table: GrantTable,
	mapping: Option<ForeignMapping>,
	port: EventChannel,
	peer: xen_sys::DomId,
	published: bool,
}
// All access is serialized by an interrupt-disabling mutex; single vCPU.
unsafe impl Send for Connection {}
static CONNECTION: InterruptTicketMutex<Option<Connection>> = InterruptTicketMutex::new(None);
const GREF: u32 = 8;
fn error(error: xen_sys::error::XenError) -> i32 {
	error!("XEN_IPC_HYPERCALL {error:?}");
	-i32::from(Errno::Io)
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_open(peer: u16) -> i32 {
	if !clock_ready() || !is_xen() {
		return -i32::from(Errno::Nosys);
	}
	// The trusted application supplies its authorized peer; a domain ID alone
	// is not proof of identity. The grant and event operations enforce this target.
	if CLAIMED.swap(true, Ordering::AcqRel) {
		return -i32::from(Errno::Busy);
	}
	let hyp = hypervisor();
	let table = match unsafe { GrantTable::initialize(&hyp, (&raw mut TABLE).cast()) } {
		Ok(v) => v,
		Err(e) => return error(e),
	};
	let peer = xen_sys::DomId(peer);
	let port = match RawEventChannelInterface::new(hyp).alloc(peer) {
		Ok(v) => v,
		Err(e) => return error(e),
	};
	if let Err(e) = EVENTS.unmask(&hyp, port.0) {
		return error(e);
	}
	*CONNECTION.lock() = Some(Connection {
		table,
		mapping: None,
		port,
		peer,
		published: false,
	});
	0
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_tx() -> usize {
	(&raw mut TX).addr()
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_port() -> u32 {
	CONNECTION.lock().as_ref().map(|c| c.port.0).unwrap_or(0)
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_publish() -> i32 {
	let mut guard = CONNECTION.lock();
	let Some(c) = guard.as_mut() else {
		return -i32::from(Errno::Inval);
	};
	match unsafe {
		c.table
			.grant(GREF, c.peer, (&raw mut TX).addr() as u64 >> 12)
	} {
		Ok(()) => {
			c.published = true;
			GREF as i32
		}
		Err(e) => error(e),
	}
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_map(gref: u32) -> usize {
	let mut guard = CONNECTION.lock();
	let Some(c) = guard.as_mut() else { return 0 };
	if c.mapping.is_some() {
		return 0;
	}
	match unsafe { ForeignMapping::map(&hypervisor(), c.peer, gref, (&raw mut RX).addr() as u64) } {
		Ok(m) => {
			c.mapping = Some(m);
			(&raw mut RX).addr()
		}
		Err(e) => {
			error(e);
			0
		}
	}
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_notify() -> i32 {
	let guard = CONNECTION.lock();
	let Some(c) = guard.as_ref() else {
		return -i32::from(Errno::Inval);
	};
	RawEventChannelInterface::new(hypervisor())
		.send(c.port)
		.map(|_| 0)
		.unwrap_or_else(error)
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_generation() -> u32 {
	GENERATION.load(Ordering::SeqCst)
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_now_ns() -> u64 {
	now_ns()
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_wait(observed: u32, deadline_ns: u64) -> i32 {
	if now_ns() >= deadline_ns {
		return -i32::from(Errno::Timedout);
	}
	WAIT_COUNT.fetch_add(1, Ordering::Relaxed);
	hermit_sync::without_interrupts(|| {
		crate::scheduler::timer_interrupts::create_timer_abs(
			crate::scheduler::timer_interrupts::Source::XenWait,
			deadline_ns.div_ceil(1000),
		);
		// No futex timeout: the shared Xen timer wakes the generation futex.
		// This avoids a stale timeout waiter being woken a second time by an IRQ.
		let result = crate::synch::futex::futex_wait(
			&GENERATION,
			observed,
			None,
			crate::synch::futex::Flags::empty(),
		);
		crate::scheduler::timer_interrupts::cancel_xen_wait();
		if now_ns() >= deadline_ns {
			-i32::from(Errno::Timedout)
		} else {
			result
		}
	})
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_mask(mask: u32) -> i32 {
	let guard = CONNECTION.lock();
	let Some(c) = guard.as_ref() else {
		return -i32::from(Errno::Inval);
	};
	let result = if mask != 0 {
		EVENTS.mask(c.port.0)
	} else {
		EVENTS.unmask(&hypervisor(), c.port.0)
	};
	result.map(|_| 0).unwrap_or_else(error)
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_revoke_probe() -> i32 {
	let guard = CONNECTION.lock();
	let Some(c) = guard.as_ref() else {
		return -i32::from(Errno::Inval);
	};
	match c.table.revoke(GREF) {
		Ok(false) => -i32::from(Errno::Busy),
		Ok(true) => 0,
		Err(e) => error(e),
	}
}
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_close() -> i32 {
	let mut guard = CONNECTION.lock();
	let Some(c) = guard.as_mut() else { return 0 };
	if let Some(m) = c.mapping.as_mut() {
		if let Err(e) = m.unmap(&hypervisor()) {
			return error(e);
		}
		c.mapping = None;
	}
	if c.published {
		match c.table.revoke(GREF) {
			Ok(false) => return -i32::from(Errno::Busy),
			Ok(true) => c.published = false,
			Err(e) => return error(e),
		}
	}
	if let Err(e) = EVENTS.mask(c.port.0) {
		return error(e);
	}
	if let Err(e) = RawEventChannelInterface::new(hypervisor()).unbind(c.port) {
		return error(e);
	}
	*guard = None;
	// Never recycle the physical mapping slots in this milestone. A new channel
	// gets a fresh domain; a failed close retains the pages until domain teardown.
	println!(
		"XEN_IPC_RELEASED grants=0 maps=0 events={} waits={} timers={}",
		EVENT_COUNT.load(Ordering::Relaxed),
		WAIT_COUNT.load(Ordering::Relaxed),
		TIMER_COUNT.load(Ordering::Relaxed)
	);
	0
}
