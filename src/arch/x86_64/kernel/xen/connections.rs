//! Bounded independent grant endpoints for single-vCPU services.
//! Slots are reusable only after successful foreign unmap and grant revocation.
//! Generation-bearing handles prevent an old owner from touching a reused slot.

use hermit_sync::InterruptTicketMutex;
use xen::grant::{ForeignMapping, GrantTable};

use super::*;

const SLOTS: usize = 64;
static mut TABLE: SharedInfoPage = SharedInfoPage([0; 4096]);
static mut TX: [SharedInfoPage; SLOTS] = [const { SharedInfoPage([0; 4096]) }; SLOTS];
static mut RX: [SharedInfoPage; SLOTS] = [const { SharedInfoPage([0; 4096]) }; SLOTS];

struct Connection {
	/// Unique nonzero handle, never reissued during this guest lifetime.
	handle: u32,
	/// Foreign mapping installed into the slot's reserved receive address.
	mapping: Option<ForeignMapping>,
	/// Event endpoint restricted to the authorized peer.
	port: EventChannel,
	/// Domain identity supplied by the trusted application.
	peer: xen_sys::DomId,
	/// Whether the transmit grant remains published.
	published: bool,
}

struct State {
	/// Single shared grant frame, initialized only for this multi-endpoint ABI.
	table: Option<GrantTable>,
	/// Active or quarantined slots, whose pages never enter the allocator.
	slots: [Option<Connection>; SLOTS],
	/// Next handle; exhaustion stops allocation instead of wrapping.
	next: u32,
}

// Single vCPU; all page ownership transitions run under this interrupt mutex.
unsafe impl Send for State {}

static STATE: InterruptTicketMutex<State> = InterruptTicketMutex::new(State {
	table: None,
	slots: [const { None }; SLOTS],
	next: 1,
});

fn index(state: &State, handle: u32) -> Option<usize> {
	state
		.slots
		.iter()
		.position(|c| c.as_ref().is_some_and(|c| c.handle == handle))
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
	if state.next >= i32::MAX as u32 {
		return -i32::from(Errno::Busy);
	}
	let Some(slot) = state.slots.iter().position(Option::is_none) else {
		return -i32::from(Errno::Busy);
	};
	let hyp = hypervisor();
	if state.table.is_none() {
		match unsafe { GrantTable::initialize(&hyp, (&raw mut TABLE).cast()) } {
			Ok(table) => state.table = Some(table),
			Err(e) => return error(e),
		}
	}
	let peer = xen_sys::DomId(peer);
	let port = match RawEventChannelInterface::new(hyp).alloc(peer) {
		Ok(port) => port,
		Err(e) => return error(e),
	};
	if let Err(e) = EVENTS.unmask(&hyp, port.0) {
		let _ = RawEventChannelInterface::new(hyp).unbind(port);
		return error(e);
	}
	let handle = state.next;
	state.next += 1;
	state.slots[slot] = Some(Connection {
		handle,
		mapping: None,
		port,
		peer,
		published: false,
	});
	handle as i32
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_tx(handle: u32) -> usize {
	index(&STATE.lock(), handle).map_or(0, |slot| tx(slot).addr())
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_port(handle: u32) -> u32 {
	let state = STATE.lock();
	index(&state, handle)
		.and_then(|slot| state.slots[slot].as_ref())
		.map_or(0, |c| c.port.0)
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_publish(handle: u32) -> i32 {
	let mut state = STATE.lock();
	let Some(slot) = index(&state, handle) else {
		return -i32::from(Errno::Inval);
	};
	let c = state.slots[slot].as_ref().unwrap();
	if c.published {
		return -i32::from(Errno::Busy);
	}
	let grant = 8 + slot as u32;
	match unsafe {
		state
			.table
			.as_ref()
			.unwrap()
			.grant(grant, c.peer, tx(slot).addr() as u64 >> 12)
	} {
		Ok(()) => {
			state.slots[slot].as_mut().unwrap().published = true;
			grant as i32
		}
		Err(e) => error(e),
	}
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_map(handle: u32, grant: u32) -> usize {
	let mut state = STATE.lock();
	let Some(slot) = index(&state, handle) else {
		return 0;
	};
	let c = state.slots[slot].as_mut().unwrap();
	if c.mapping.is_some() {
		return 0;
	}
	match unsafe { ForeignMapping::map(&hypervisor(), c.peer, grant, rx(slot).addr() as u64) } {
		Ok(mapping) => {
			c.mapping = Some(mapping);
			rx(slot).addr()
		}
		Err(_) => 0,
	}
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_notify(handle: u32) -> i32 {
	let state = STATE.lock();
	let Some(slot) = index(&state, handle) else {
		return -i32::from(Errno::Inval);
	};
	RawEventChannelInterface::new(hypervisor())
		.send(state.slots[slot].as_ref().unwrap().port)
		.map(|_| 0)
		.unwrap_or_else(error)
}

#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_connection_close(handle: u32) -> i32 {
	let mut state = STATE.lock();
	let Some(slot) = index(&state, handle) else {
		return -i32::from(Errno::Inval);
	};
	let c = state.slots[slot].as_mut().unwrap();
	if let Some(mapping) = c.mapping.as_mut() {
		if let Err(e) = mapping.unmap(&hypervisor()) {
			return error(e);
		}
		c.mapping = None;
	}
	if c.published {
		match state.table.as_ref().unwrap().revoke(8 + slot as u32) {
			Ok(false) => return -i32::from(Errno::Busy),
			Ok(true) => state.slots[slot].as_mut().unwrap().published = false,
			Err(e) => return error(e),
		}
	}
	let port = state.slots[slot].as_ref().unwrap().port;
	if let Err(e) = EVENTS.mask(port.0) {
		return error(e);
	}
	if let Err(e) = RawEventChannelInterface::new(hypervisor()).unbind(port) {
		return error(e);
	}
	// No peer retains TX, and RX is unmapped. Future accesses must carry a new handle.
	state.slots[slot] = None;
	0
}
