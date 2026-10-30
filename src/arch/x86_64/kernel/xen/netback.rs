//! Bounded raw Ethernet backend for controller-selected ordinary Linux vifs.
//! Each client owns two ring mappings and one event binding in a four-slot
//! registry shared in implementation with IPC endpoints. Packet data uses one
//! synchronous Xen grant-copy operation and private bounce page, never retained
//! foreign data mappings. Each data call handles at most one descriptor.
//!
//! Controller contract: its trusted Xen lifecycle owner selects each peer and
//! retires the old lease before permitting destruction/recreation or domain-ID
//! reuse. A raw domid is not an incarnation or policy identity. Lease handles
//! never repeat, old handles are rejected after retirement, and failed cleanup
//! retains its charge/address space rather than authorizing a replacement.
//! This generic driver does not discover or authorize clients from peer claims.
//!
//! Trusted effects: Xen mappings/copies/events, coherent volatile memory and
//! header atomics, clock and exclusive guard. Registry tokens must stay with
//! these exact static slots/mappings and selected peer; bus/ring/descriptor and
//! retirement decisions execute the verified cores. Uncertain effects quarantine
//! one client; no peer-state waiting loop runs while other clients need service.

use alloc::format;
use alloc::string::String;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, fence};

use xen::grant::{ForeignMapping, copy_from_grant, copy_to_grant};
use xen::io::net::bus::{BackendAction, Life};
use xen::io::net::queue::Back;
use xen::io::net::{self as wire};
use xen::resources::{Origin, Registry, Retirement, Token};

use super::netring::Ring;
use super::store::{Store, Subscription};
use super::*;

/// Includes clients that are opening, active, closing or quarantined.
const CLIENTS: usize = 4;
/// Absolute bound for one explicit XenStore control operation/batch.
const CONTROL_NS: u64 = 500_000_000;
static ORIGIN: Origin = Origin::new();
static mut TX_RINGS: [SharedInfoPage; CLIENTS] = [const { SharedInfoPage([0; 4096]) }; CLIENTS];
static mut RX_RINGS: [SharedInfoPage; CLIENTS] = [const { SharedInfoPage([0; 4096]) }; CLIENTS];
/// Never granted or foreign-mapped; all driver calls serialize use of this page.
static mut DATA: SharedInfoPage = SharedInfoPage([0; 4096]);
static BUSY: AtomicBool = AtomicBool::new(false);

struct Owned {
	/// Serialized by Guard; IRQ paths never access client or resource metadata.
	state: UnsafeCell<Devices>,
}
// The nonblocking atomic guard excludes reentry; no interrupt lock spans XenStore
// sleeping. Order is driver guard then the domain XenStore guard, never reversed.
unsafe impl Sync for Owned {}
static DEVICES: Owned = Owned {
	state: UnsafeCell::new(Devices {
		registry: None,
		clients: [const { None }; CLIENTS],
	}),
};

struct Guard;

impl Guard {
	/// Concurrent/reentrant attempts return Busy, never spin over a sleeping owner.
	fn acquire() -> Result<Self, i32> {
		BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
			.map(|_| Self)
			.map_err(|_| -i32::from(Errno::Busy))
	}
}

impl Drop for Guard {
	fn drop(&mut self) {
		BUSY.store(false, Ordering::Release);
	}
}

struct Devices {
	/// Unique-origin fixed charging shared with the IPC implementation.
	registry: Option<Registry>,
	/// Every real resource is charged before its first effect, including failures.
	clients: [Option<Client>; CLIENTS],
}

struct Client {
	/// Exact local slot, nonreused handle and controller-selected peer lifetime.
	owner: Token,
	/// Cheap handle to the one domain-owned XenStore connection.
	xs: Store,
	/// Relative toolstack-owned backend node for this client's vif/0.
	back: String,
	/// Exact validated absolute frontend path, retained as private owned bytes.
	front: String,
	/// Bounded state subscription; event paths never choose a control node.
	watch: Option<Subscription>,
	/// Volatile opening/readiness/closure; peer state cannot revive a failed owner.
	life: Life,
	/// No new effects after cleanup begins; uncertain cleanup is never replayed.
	retirement: Retirement,
	/// First persistent foreign ring mapping, installed before the next effect.
	tx_mapping: Option<ForeignMapping>,
	/// Second persistent foreign ring mapping, installed before the next effect.
	rx_mapping: Option<ForeignMapping>,
	/// Exact binding to the selected frontend's event port, installed before unmask.
	port: Option<EventChannel>,
	/// Backend-owned TX request consumer/response producer.
	tx: Back,
	/// Backend-owned RX request consumer/response producer.
	rx: Back,
}

/// Native errno convention used by all Xen driver ABIs.
fn io() -> i32 {
	-i32::from(Errno::Io)
}

/// Static address belongs only to this token's bounded slot; never allocator RAM.
fn tx(slot: usize) -> *mut u8 {
	unsafe {
		(&raw mut TX_RINGS)
			.cast::<SharedInfoPage>()
			.add(slot)
			.cast()
	}
}

/// Static address remains reserved through failed/quarantined foreign unmap.
fn rx(slot: usize) -> *mut u8 {
	unsafe {
		(&raw mut RX_RINGS)
			.cast::<SharedInfoPage>()
			.add(slot)
			.cast()
	}
}

impl Devices {
	/// Resolve only a retained runtime owner, never mint authority from a label.
	fn index(&self, handle: u32) -> Option<usize> {
		let slot = self.registry.as_ref()?.resolve(handle)?;
		let client = self.clients.get(slot)?.as_ref()?;
		(client.owner.handle() == handle).then_some(slot)
	}

	/// Stop data before cleanup. Our foreign ring mappings can be withdrawn
	/// unilaterally; no peer cooperation or polling loop is needed to release
	/// them. Unknown effect errors retain the entire slot until domain teardown.
	fn close(&mut self, handle: u32) -> Result<(), i32> {
		let slot = self.index(handle).ok_or(-i32::from(Errno::Inval))?;
		let client = self.clients[slot].as_mut().ok_or_else(io)?;
		if !client.retirement.begin() || !client.life.close() {
			return Err(io());
		}
		let result = client.release();
		if result.is_err() {
			client.quarantine();
			return result;
		}
		if !client.life.released(true) {
			client.quarantine();
			return Err(io());
		}
		let client = self.clients[slot].take().ok_or_else(io)?;
		let registry = self.registry.as_mut().ok_or_else(io)?;
		match registry.release(client.owner, true) {
			Ok(()) => {
				println!("XEN_NETBACK_RELEASED handle={handle} maps=0 ports=0");
				Ok(())
			}
			Err(owner) => {
				let mut client = Client { owner, ..client };
				client.quarantine();
				self.clients[slot] = Some(client);
				Err(io())
			}
		}
	}
}

impl Client {
	/// Retain every charge and deny all future effects before reporting ambiguity.
	fn quarantine(&mut self) {
		self.life.fail();
		self.retirement.quarantine();
	}

	/// Notify using the peer's standard response-event threshold after publishing
	/// the matching response and a full Xen ring barrier.
	fn notify(&self, ring: &Ring<'_>, old: u32, next: u32) -> Result<(), i32> {
		fence(Ordering::SeqCst);
		if xen::io::store::ring::event_needed(old, next, ring.response_event()) {
			RawEventChannelInterface::new(hypervisor())
				.send(self.port.ok_or_else(io)?)
				.map_err(|_| io())?;
		}
		Ok(())
	}

	/// Read complete frontend parameters in one standard transaction before
	/// mapping anything. No automatic retry/replay follows a failed transaction.
	fn connect(&mut self, peer_state: &str, deadline: u64) -> Result<(), i32> {
		let front = &self.front;
		let (tx_text, rx_text, port_text) = self.xs.transaction(deadline, |scope| {
			if scope.read(&format!("{front}/request-rx-copy"))? != "1" {
				return Err(io());
			}
			let tx = scope.read(&format!("{front}/tx-ring-ref"))?;
			let rx = scope.read(&format!("{front}/rx-ring-ref"))?;
			let port = scope.read(&format!("{front}/event-channel"))?;
			Ok((tx, rx, port))
		})?;
		let tx_grant = wire::backend::number_claim(tx_text.as_bytes()).ok_or_else(io)?;
		let rx_grant = wire::backend::number_claim(rx_text.as_bytes()).ok_or_else(io)?;
		let port = wire::backend::number_claim(port_text.as_bytes()).ok_or_else(io)?;
		let peer = xen_sys::DomId(self.owner.peer());
		let slot = self.owner.slot();
		// Charge and owner installation preceded this first mapping. On partial
		// failure all installed mappings remain in the client; no reopen occurs.
		self.tx_mapping = Some(
			unsafe { ForeignMapping::map(&hypervisor(), peer, tx_grant, tx(slot).addr() as u64) }
				.map_err(|_| io())?,
		);
		self.rx_mapping = Some(
			unsafe { ForeignMapping::map(&hypervisor(), peer, rx_grant, rx(slot).addr() as u64) }
				.map_err(|_| io())?,
		);
		let event = RawEventChannelInterface::new(hypervisor())
			.bind_interdomain(peer, EventChannel(port))
			.map_err(|_| io())?;
		self.port = Some(event);
		EVENTS.unmask(&hypervisor(), event.0).map_err(|_| io())?;
		// Check both private producer shadows/occupancies before readiness.
		{
			let tx = unsafe { Ring::borrow(tx(slot), self.tx_mapping.as_ref().ok_or_else(io)?) }?;
			let _ = self
				.tx
				.request(tx.response_producer(), tx.request_producer())
				.map_err(|_| io())?;
			let rx = unsafe { Ring::borrow(rx(slot), self.rx_mapping.as_ref().ok_or_else(io)?) }?;
			let _ = self
				.rx
				.request(rx.response_producer(), rx.request_producer())
				.map_err(|_| io())?;
		}
		self.xs
			.write(&format!("{}/state", self.back), "4", deadline)?;
		if !self.life.connected(peer_state.as_bytes(), true) {
			return Err(io());
		}
		println!(
			"XEN_NETBACK_READY peer={peer} handle={handle}",
			peer = self.owner.peer(),
			handle = self.owner.handle()
		);
		Ok(())
	}

	/// Explicit bounded close. Every Option is cleared only after successful
	/// completion; no destructor retries failed unmaps or event release.
	fn release(&mut self) -> Result<(), i32> {
		let deadline = now_ns().saturating_add(CONTROL_NS);
		self.xs
			.write(&format!("{}/state", self.back), "5", deadline)?;
		if let Some(mapping) = self.tx_mapping.as_mut() {
			mapping.unmap(&hypervisor()).map_err(|_| io())?;
			self.tx_mapping = None;
		}
		if let Some(mapping) = self.rx_mapping.as_mut() {
			mapping.unmap(&hypervisor()).map_err(|_| io())?;
			self.rx_mapping = None;
		}
		if let Some(port) = self.port {
			EVENTS.mask(port.0).map_err(|_| io())?;
			RawEventChannelInterface::new(hypervisor())
				.unbind(port)
				.map_err(|_| io())?;
			self.port = None;
		}
		self.xs
			.write(&format!("{}/state", self.back), "6", deadline)?;
		if let Some(watch) = self.watch.take() {
			watch.close(deadline)?;
		}
		Ok(())
	}

	/// Consume one TX request into private memory via synchronous grant copy,
	/// then publish its exact native completion. The caller buffer is never
	/// granted; copying it occurs while the global bounce-page guard is held.
	fn receive(&mut self, buffer: *mut u8) -> Result<usize, i32> {
		if !self.retirement.usable() {
			return Err(io());
		}
		if !self.life.usable() {
			return Err(-i32::from(Errno::Again));
		}
		let ring = unsafe {
			Ring::borrow(
				tx(self.owner.slot()),
				self.tx_mapping.as_ref().ok_or_else(io)?,
			)
		}?;
		let Some(slot) = ring.back_request(&self.tx)? else {
			return Ok(0);
		};
		let bytes = ring.read::<12>(&slot)?;
		let packet = wire::backend::transmit(&bytes).map_err(|_| io())?;
		let length = packet.len();
		let copied = unsafe {
			copy_from_grant(
				&hypervisor(),
				xen_sys::DomId(self.owner.peer()),
				packet.grant(),
				packet.offset(),
				length,
				(&raw mut DATA).addr() as u64 >> 12,
			)
		}
		.is_ok();
		ring.write(&slot, &packet.response(copied))?;
		let old = slot.current();
		let next = slot.published();
		if !self.tx.responded(slot) {
			return Err(io());
		}
		ring.publish_response(next);
		self.notify(&ring, old, next)?;
		if !copied {
			return Ok(0);
		}
		unsafe {
			ptr::copy_nonoverlapping((&raw const DATA).cast(), buffer, usize::from(length));
		}
		Ok(usize::from(length))
	}

	/// Copy one local frame into one supplied receive grant; missing requests
	/// are backpressure. A failed copy reports an error completion, never bytes.
	fn send(&mut self, buffer: *const u8, bytes: usize) -> Result<bool, i32> {
		let length = wire::backend::packet_length(bytes).ok_or(-i32::from(Errno::Inval))?;
		if !self.retirement.usable() {
			return Err(io());
		}
		if !self.life.usable() {
			return Err(-i32::from(Errno::Again));
		}
		let ring = unsafe {
			Ring::borrow(
				rx(self.owner.slot()),
				self.rx_mapping.as_ref().ok_or_else(io)?,
			)
		}?;
		let Some(slot) = ring.back_request(&self.rx)? else {
			return Ok(false);
		};
		let request = wire::backend::receive_buffer(&ring.read::<8>(&slot)?);
		unsafe {
			ptr::copy_nonoverlapping(buffer, (&raw mut DATA).cast(), usize::from(length));
		}
		let copied = unsafe {
			copy_to_grant(
				&hypervisor(),
				xen_sys::DomId(self.owner.peer()),
				request.grant(),
				length,
				(&raw mut DATA).addr() as u64 >> 12,
			)
		}
		.is_ok();
		ring.write(
			&slot,
			&request
				.response(usize::from(length), copied)
				.map_err(|_| io())?,
		)?;
		let old = slot.current();
		let next = slot.published();
		if !self.rx.responded(slot) {
			return Err(io());
		}
		ring.publish_response(next);
		self.notify(&ring, old, next)?;
		if copied { Ok(true) } else { Err(io()) }
	}
}

/// Reserve one explicitly authorized frontend lifetime; no peer-state wait loop.
/// The controller must retire it before allowing this domain ID to be reused.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_netback_open(peer: u16) -> i32 {
	let _guard = match Guard::acquire() {
		Ok(value) => value,
		Err(error) => return error,
	};
	if !is_xen() || !clock_ready() {
		return -i32::from(Errno::Nosys);
	}
	let state = unsafe { &mut *DEVICES.state.get() };
	if state.registry.is_none() {
		state.registry = ORIGIN.registry(CLIENTS);
	}
	let Some(registry) = state.registry.as_mut() else {
		return io();
	};
	if registry.contains_peer(peer) {
		return -i32::from(Errno::Busy);
	}
	let Some(owner) = registry.reserve(peer) else {
		return -i32::from(Errno::Busy);
	};
	let slot = owner.slot();
	let handle = owner.handle();
	let result = (|| {
		let deadline = now_ns().saturating_add(CONTROL_NS);
		let mut xs = Store::open()?;
		let own = xs.read("domid", deadline)?;
		let own_number: u16 = wire::backend::number_claim(own.as_bytes())
			.and_then(|value| u16::try_from(value).ok())
			.ok_or_else(io)?;
		if !wire::identity::domain_matches(own.as_bytes(), own_number) {
			return Err(io());
		}
		let peer_digits = format!("{peer}");
		let back = format!("backend/vif/{peer}/0");
		let front = xs.read(&format!("{back}/frontend"), deadline)?;
		if !wire::identity::frontend_linked(peer_digits.as_bytes(), front.as_bytes()) {
			return Err(io());
		}
		let observed_peer = xs.read(&format!("{back}/frontend-id"), deadline)?;
		if !wire::identity::domain_matches(observed_peer.as_bytes(), peer) {
			return Err(io());
		}
		let reciprocal = xs.read(&format!("{front}/backend"), deadline)?;
		if !wire::identity::backend_linked(
			own_number,
			own.as_bytes(),
			peer_digits.as_bytes(),
			reciprocal.as_bytes(),
		) {
			return Err(io());
		}
		let backend_id = xs.read(&format!("{front}/backend-id"), deadline)?;
		if !wire::identity::domain_matches(backend_id.as_bytes(), own_number) {
			return Err(io());
		}
		let mut life = Life::new();
		if !life.begin() {
			return Err(io());
		}
		state.clients[slot] = Some(Client {
			owner,
			xs,
			back,
			front,
			watch: None,
			life,
			retirement: Retirement::new(),
			tx_mapping: None,
			rx_mapping: None,
			port: None,
			tx: Back::tx(),
			rx: Back::rx(),
		});
		let client = state.clients[slot].as_mut().ok_or_else(io)?;
		client.watch = Some(
			client
				.xs
				.subscribe(&format!("{}/state", client.front), deadline)?,
		);
		let back = &client.back;
		client.xs.transaction(deadline, |scope| {
			for (key, value) in [
				("feature-rx-copy", "1"),
				("feature-rx-flip", "0"),
				("feature-no-csum-offload", "1"),
				("feature-ipv6-csum-offload", "0"),
				("feature-sg", "0"),
				("feature-gso-tcpv4", "0"),
				("feature-gso-tcpv6", "0"),
				("feature-split-event-channels", "0"),
				("multi-queue-max-queues", "1"),
				("hotplug-status", "connected"),
				("state", "2"),
			] {
				scope.write(&format!("{back}/{key}"), value)?;
			}
			Ok(())
		})
	})();
	if let Err(error) = result {
		if let Some(client) = state.clients[slot].as_mut() {
			client.quarantine();
		}
		// Even an abandoned pre-publication token remains charged. No real
		// resource can be silently assigned to this reserved slot again.
		return error;
	}
	println!("XEN_NETBACK_OFFER peer={peer} handle={handle} slot={slot}");
	handle as i32
}

/// One bounded control step: 0 waiting, 1 closed/released, 2 connected. Malformed
/// or backward peer state quarantines only this owner. No automatic reconnect.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_netback_progress(handle: u32) -> i32 {
	let _guard = match Guard::acquire() {
		Ok(value) => value,
		Err(error) => return error,
	};
	let state = unsafe { &mut *DEVICES.state.get() };
	let Some(slot) = state.index(handle) else {
		return -i32::from(Errno::Inval);
	};
	let Some(client) = state.clients[slot].as_mut() else {
		return io();
	};
	if !client.retirement.usable() {
		return io();
	}
	let deadline = now_ns().saturating_add(CONTROL_NS);
	let result = (|| {
		let watch = client.watch.as_mut().ok_or_else(io)?;
		if !watch.changed(deadline)? {
			return Ok(if client.life.usable() { 2 } else { 0 });
		}
		let peer_state = watch.read(deadline)?;
		match wire::bus::backend_action(peer_state.as_bytes(), client.life.usable()) {
			BackendAction::Await => Ok(0),
			BackendAction::Run => Ok(2),
			BackendAction::Close => Ok(1),
			BackendAction::Connect => {
				client.connect(&peer_state, deadline)?;
				Ok(2)
			}
			BackendAction::Reject => Err(io()),
		}
	})();
	match result {
		Ok(1) => match state.close(handle) {
			Ok(()) => 1,
			Err(error) => error,
		},
		Ok(status) => status,
		Err(error) => {
			client.quarantine();
			error
		}
	}
}

/// Receive at most one copied client frame; zero means no packet available.
/// # Safety
/// buffer remains valid for 4096 writable bytes and does not alias driver pages.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sys_xen_netback_receive(
	handle: u32,
	buffer: *mut u8,
	capacity: usize,
) -> i32 {
	let _guard = match Guard::acquire() {
		Ok(value) => value,
		Err(error) => return error,
	};
	if buffer.is_null() || capacity < 4096 {
		return -i32::from(Errno::Inval);
	}
	let state = unsafe { &mut *DEVICES.state.get() };
	let Some(slot) = state.index(handle) else {
		return -i32::from(Errno::Inval);
	};
	let Some(client) = state.clients[slot].as_mut() else {
		return io();
	};
	match client.receive(buffer) {
		Ok(length) => length as i32,
		Err(error) => {
			if error != -i32::from(Errno::Again) {
				client.quarantine();
			}
			error
		}
	}
}

/// Send one copied frame; 0 backpressure, 1 local copy completion, negative errno.
/// # Safety
/// buffer remains valid for bytes readable bytes and does not alias driver pages.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sys_xen_netback_send(handle: u32, buffer: *const u8, bytes: usize) -> i32 {
	let _guard = match Guard::acquire() {
		Ok(value) => value,
		Err(error) => return error,
	};
	if buffer.is_null() {
		return -i32::from(Errno::Inval);
	}
	let state = unsafe { &mut *DEVICES.state.get() };
	let Some(slot) = state.index(handle) else {
		return -i32::from(Errno::Inval);
	};
	let Some(client) = state.clients[slot].as_mut() else {
		return io();
	};
	match client.send(buffer, bytes) {
		Ok(copied) => i32::from(copied),
		Err(error) => {
			if error != -i32::from(Errno::Again) && error != -i32::from(Errno::Inval) {
				client.quarantine();
			}
			error
		}
	}
}

/// Explicitly stop and retire a controller-owned interface before domain reuse.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_netback_close(handle: u32) -> i32 {
	let _guard = match Guard::acquire() {
		Ok(value) => value,
		Err(error) => return error,
	};
	let state = unsafe { &mut *DEVICES.state.get() };
	state.close(handle).map_or_else(|error| error, |()| 0)
}
