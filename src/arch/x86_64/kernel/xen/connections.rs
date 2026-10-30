//! Bounded independent grant endpoints for single-vCPU services.
//! Slots are reusable only after successful foreign unmap and grant revocation.
//! Generation-bearing handles prevent an old owner from touching a reused slot.

use hermit_sync::InterruptTicketMutex;
use xen::grant::{ForeignMapping, GrantTable};
use xen::resources::{Origin, Registry, Retirement, Token};

use super::*;

const SLOTS: usize = 64;
static ORIGIN: Origin = Origin::new();
static mut TX: [SharedInfoPage; SLOTS] = [const { SharedInfoPage([0; 4096]) }; SLOTS];
static mut RX: [SharedInfoPage; SLOTS] = [const { SharedInfoPage([0; 4096]) }; SLOTS];

struct Connection {
	/// Charged slot/domain/lifetime token from the shared verified registry.
	owner: Token,
	/// New effects stop before cleanup; ambiguous failures forbid replay.
	retirement: Retirement,
	/// Foreign mapping installed into the slot's reserved receive address.
	mapping: Option<ForeignMapping>,
	/// Event endpoint restricted to the authorized peer.
	port: EventChannel,
	/// Whether the transmit grant remains published.
	published: bool,
}

struct State {
	/// Single shared grant frame, initialized only for this multi-endpoint ABI.
	table: Option<GrantTable>,
	/// Active or quarantined slots, whose pages never enter the allocator.
	slots: [Option<Connection>; SLOTS],
	/// Shared verified accounting, initialized before the first Xen allocation.
	registry: Option<Registry>,
}

// Single vCPU; all page ownership transitions run under this interrupt mutex.
unsafe impl Send for State {}

static STATE: InterruptTicketMutex<State> = InterruptTicketMutex::new(State {
	table: None,
	slots: [const { None }; SLOTS],
	registry: None,
});

/// Resolve only a retained owner; raw handle values never create a token. The
/// same interrupt guard preserves registry/object correspondence through use.
fn index(state: &State, handle: u32) -> Option<usize> {
	let slot = state.registry.as_ref()?.resolve(handle)?;
	let connection = state.slots.get(slot)?.as_ref()?;
	(connection.owner.handle() == handle).then_some(slot)
}

/// Deny publication, mapping, notification and page discovery after cleanup starts.
fn active(state: &State, handle: u32) -> Option<usize> {
	let slot = index(state, handle)?;
	state
		.slots
		.get(slot)?
		.as_ref()?
		.retirement
		.usable()
		.then_some(slot)
}

fn error(_: xen_sys::error::XenError) -> i32 {
	-i32::from(Errno::Io)
}

fn tx(slot: usize) -> *mut u8 {
	unsafe { (&raw mut TX).cast::<SharedInfoPage>().add(slot).cast() }
}

fn rx(slot: usize) -> *mut u8 {
	unsafe { (&raw mut RX).cast::<SharedInfoPage>().add(slot).cast() }
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_open(peer: u16) -> i32 {
	if !clock_ready() || !is_xen() {
		return -i32::from(Errno::Nosys);
	}
	let mut state = STATE.lock();
	let hyp = hypervisor();
	if state.table.is_none() {
		match super::grants::table() {
			Ok(table) => state.table = Some(table),
			Err(e) => return error(e),
		}
	}
	if state.registry.is_none() {
		state.registry = ORIGIN.registry(SLOTS);
	}
	let Some(registry) = state.registry.as_mut() else {
		return -i32::from(Errno::Io);
	};
	let Some(owner) = registry.reserve(peer) else {
		return -i32::from(Errno::Busy);
	};
	let slot = owner.slot();
	let handle = owner.handle();
	// Charge before attempting the first Xen resource. Failed/abandoned opens
	// keep their slot charged even if no runtime object could be installed.
	let port = match RawEventChannelInterface::new(hyp).alloc(xen_sys::DomId(owner.peer())) {
		Ok(port) => port,
		Err(e) => return error(e),
	};
	let Some(target) = state.slots.get_mut(slot) else {
		return -i32::from(Errno::Io);
	};
	*target = Some(Connection {
		owner,
		retirement: Retirement::new(),
		mapping: None,
		port,
		published: false,
	});
	if let Err(e) = EVENTS.unmask(&hyp, port.0) {
		if let Some(connection) = state.slots.get_mut(slot).and_then(Option::as_mut) {
			connection.retirement.quarantine();
		}
		return error(e);
	}
	handle as i32
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_tx(handle: u32) -> usize {
	active(&STATE.lock(), handle).map_or(0, |slot| tx(slot).addr())
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_port(handle: u32) -> u32 {
	let state = STATE.lock();
	active(&state, handle)
		.and_then(|slot| state.slots[slot].as_ref())
		.map_or(0, |c| c.port.0)
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_publish(handle: u32) -> i32 {
	let mut state = STATE.lock();
	let Some(slot) = active(&state, handle) else {
		return -i32::from(Errno::Inval);
	};
	let Some(c) = state.slots[slot].as_ref() else {
		return -i32::from(Errno::Io);
	};
	if c.published {
		return -i32::from(Errno::Busy);
	}
	let grant = 8 + slot as u32;
	let Some(table) = state.table.as_ref() else {
		return -i32::from(Errno::Io);
	};
	match unsafe {
		table.grant(
			grant,
			xen_sys::DomId(c.owner.peer()),
			tx(slot).addr() as u64 >> 12,
		)
	} {
		Ok(()) => {
			let Some(c) = state.slots[slot].as_mut() else {
				return -i32::from(Errno::Io);
			};
			c.published = true;
			grant as i32
		}
		Err(e) => {
			if let Some(c) = state.slots[slot].as_mut() {
				c.retirement.quarantine();
			}
			error(e)
		}
	}
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_map(handle: u32, grant: u32) -> usize {
	let mut state = STATE.lock();
	let Some(slot) = active(&state, handle) else {
		return 0;
	};
	let Some(c) = state.slots[slot].as_mut() else {
		return 0;
	};
	if c.mapping.is_some() {
		return 0;
	}
	match unsafe {
		ForeignMapping::map(
			&hypervisor(),
			xen_sys::DomId(c.owner.peer()),
			grant,
			rx(slot).addr() as u64,
		)
	} {
		Ok(mapping) => {
			c.mapping = Some(mapping);
			rx(slot).addr()
		}
		Err(_) => {
			c.retirement.quarantine();
			0
		}
	}
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_notify(handle: u32) -> i32 {
	let mut state = STATE.lock();
	let Some(slot) = active(&state, handle) else {
		return -i32::from(Errno::Inval);
	};
	let Some(c) = state.slots[slot].as_mut() else {
		return -i32::from(Errno::Io);
	};
	match RawEventChannelInterface::new(hypervisor()).send(c.port) {
		Ok(()) => 0,
		Err(e) => {
			c.retirement.quarantine();
			error(e)
		}
	}
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_close(handle: u32) -> i32 {
	let mut state = STATE.lock();
	let Some(slot) = index(&state, handle) else {
		return -i32::from(Errno::Inval);
	};
	let Some(c) = state.slots[slot].as_mut() else {
		return -i32::from(Errno::Io);
	};
	if !c.retirement.begin() {
		return -i32::from(Errno::Io);
	}
	if let Some(mapping) = c.mapping.as_mut() {
		if let Err(e) = mapping.unmap(&hypervisor()) {
			c.retirement.quarantine();
			return error(e);
		}
		c.mapping = None;
	}
	let published = c.published;
	if published {
		let Some(table) = state.table.as_ref() else {
			return -i32::from(Errno::Io);
		};
		match table.revoke(8 + slot as u32) {
			Ok(false) => return -i32::from(Errno::Busy),
			Ok(true) => {
				if let Some(c) = state.slots[slot].as_mut() {
					c.published = false;
				}
			}
			Err(e) => {
				if let Some(c) = state.slots[slot].as_mut() {
					c.retirement.quarantine();
				}
				return error(e);
			}
		}
	}
	let Some(c) = state.slots[slot].as_mut() else {
		return -i32::from(Errno::Io);
	};
	if let Err(e) = EVENTS.mask(c.port.0) {
		c.retirement.quarantine();
		return error(e);
	}
	if let Err(e) = RawEventChannelInterface::new(hypervisor()).unbind(c.port) {
		c.retirement.quarantine();
		return error(e);
	}
	// Only confirmed unmap/revoke/unbind retires the charged lifetime. All
	// earlier errors retained the owner; Busy alone permits a safe retry.
	let Some(c) = state.slots[slot].take() else {
		return -i32::from(Errno::Io);
	};
	let Some(registry) = state.registry.as_mut() else {
		return -i32::from(Errno::Io);
	};
	match registry.release(c.owner, true) {
		Ok(()) => 0,
		Err(owner) => {
			let mut retirement = Retirement::new();
			retirement.quarantine();
			state.slots[slot] = Some(Connection {
				owner,
				retirement,
				mapping: None,
				port: c.port,
				published: false,
			});
			-i32::from(Errno::Io)
		}
	}
}
