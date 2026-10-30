//! Raw Ethernet over the standard Xen netif frontend, without a network stack.
//! One toolstack-provisioned vif/0, one fixed TX and RX data page, no offloads.
//! Pages remain pinned on every error. Data polling never waits for a peer;
//! watches and deadlines are used only during explicit open/close operations.
//!
//! Effect boundary: the verified netif core supplies exact descriptor bytes,
//! bounded offsets, ring counter decisions, identity validation and loan/lifecycle
//! transitions. This adapter must bind each object to the same static page,
//! grant and configured peer for its entire lifetime. Volatile byte snapshots,
//! coherent Xen memory, atomic barriers, grant revocation, event binding and
//! monotonic clock/scheduler correspondence remain trusted. No Rust reference
//! aliases a page while a foreign mapping may exist; RX copies follow successful
//! revoke of the exact grant. IRQ handlers only advance the shared generation.

use alloc::format;
use alloc::string::String;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, fence};

use xen::grant::GrantTable;
use xen::io::net::bus::{Life, State};
use xen::io::net::loans::{Completion, Direction, Page};
use xen::io::net::queue::Front;
use xen::io::net::{self as wire, Receive};

use super::netring::Ring;
use super::store::Store;
use super::*;

// Disjoint from IPC 8..72 and block 128..130, in the existing shared grant frame.
const TX_RING_GRANT: u32 = 144;
const RX_RING_GRANT: u32 = 145;
const TX_DATA_GRANT: u32 = 146;
const RX_DATA_GRANT: u32 = 147;
const TIMEOUT_NS: u64 = 5_000_000_000;
static mut TX_RING: SharedInfoPage = SharedInfoPage([0; 4096]);
static mut RX_RING: SharedInfoPage = SharedInfoPage([0; 4096]);
static mut TX_DATA: SharedInfoPage = SharedInfoPage([0; 4096]);
static mut RX_DATA: SharedInfoPage = SharedInfoPage([0; 4096]);

/// Nonblocking exclusive access; driver guard precedes the shared XenStore guard.
static BUSY: AtomicBool = AtomicBool::new(false);
/// Exclusive attachment; only fully confirmed teardown permits another open.
static CLAIMED: AtomicBool = AtomicBool::new(false);

struct Owned {
	/// Access requires Guard; neither IRQ callbacks nor other drivers borrow it.
	device: UnsafeCell<Option<Device>>,
}
// The atomic guard serializes all access and excludes IRQ access. Static pages
// and resources remain installed even if an operation unwinds/fails.
unsafe impl Sync for Owned {}
static DEVICE: Owned = Owned {
	device: UnsafeCell::new(None),
};

struct Guard;

impl Guard {
	/// Reject concurrent/reentrant callers; never spin across a sleeping owner.
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

struct Device {
	/// Local handle to the sole domain-owned XenStore stream.
	xs: Store,
	/// Toolstack-selected absolute backend path, validated before following it.
	back: String,
	/// Exact peer selected by the caller, never chosen by an observed descriptor.
	peer: xen_sys::DomId,
	/// Shared grant table mapping, with only this driver's disjoint entries used.
	table: GrantTable,
	/// One combined standard netif event channel.
	port: EventChannel,
	/// Volatile connection admission and explicit retirement.
	life: Life,
	/// Frontend-owned TX counter shadows.
	tx: Front,
	/// Frontend-owned RX counter shadows.
	rx: Front,
	/// Exact outgoing data page's grant ownership.
	tx_page: Page,
	/// Exact incoming data page's grant ownership and pending packet metadata.
	rx_page: Page,
}

/// Preserve the platform's errno convention.
fn io() -> i32 {
	-i32::from(Errno::Io)
}

/// Wait on bounded watch hints, rereading the configured peer's exact state.
fn state(
	xs: &mut Store,
	backend: &str,
	first: State,
	second: State,
	deadline: u64,
) -> Result<String, i32> {
	let mut watch = xs.watch(&format!("{backend}/state"), deadline)?;
	loop {
		let value = watch.read(deadline)?;
		if first.matches(value.as_bytes()) || second.matches(value.as_bytes()) {
			watch.close(deadline)?;
			return Ok(value);
		}
		watch.wait(deadline)?;
	}
}

impl Device {
	/// Quarantine all potentially offered pages before reporting an error.
	fn fail(&mut self) {
		self.life.fail();
		self.tx_page.quarantine();
		self.rx_page.quarantine();
	}

	/// Notify only when Xen's standard event threshold requests it.
	fn notify(&self, ring: &Ring<'_>, old: u32, next: u32) -> Result<(), i32> {
		fence(Ordering::SeqCst);
		if xen::io::store::ring::event_needed(old, next, ring.request_event()) {
			RawEventChannelInterface::new(hypervisor())
				.send(self.port)
				.map_err(|_| io())?;
		}
		Ok(())
	}

	/// Offer exactly the reusable RX page. Idle receive waiting has no timeout;
	/// the finite reclamation budget starts on a validated completion.
	fn post_receive(&mut self) -> Result<(), i32> {
		if !self.rx_page.reusable() {
			return Ok(());
		}
		let ring = unsafe { Ring::borrow((&raw mut RX_RING).cast::<u8>(), &self.life) }?;
		let slot = self
			.rx
			.request(ring.request_producer())
			.map_err(|_| io())?
			.ok_or_else(io)?;
		if !self.rx_page.offer(u64::MAX) {
			return Err(io());
		}
		unsafe {
			self.table
				.grant(
					RX_DATA_GRANT,
					self.peer,
					(&raw mut RX_DATA).addr() as u64 >> 12,
				)
				.map_err(|_| io())?;
		}
		ring.write(&slot, &wire::rx_request(RX_DATA_GRANT, 0))?;
		let old = slot.current();
		let next = slot.published();
		if !self.rx.posted(slot) {
			return Err(io());
		}
		ring.publish_request(next);
		self.notify(&ring, old, next)
	}

	/// Accept at most one TX completion and make one revoke attempt. A peer
	/// retaining its mapping returns immediately and is quarantined on expiry.
	fn poll_transmit(&mut self) -> Result<(), i32> {
		let ring = unsafe { Ring::borrow((&raw mut TX_RING).cast::<u8>(), &self.life) }?;
		if self.tx_page.awaiting() {
			if let Some(slot) = ring.front_response(&self.tx)? {
				let bytes = ring.read::<4>(&slot)?;
				let sent = wire::tx_response(&bytes, 0).map_err(|_| io())?;
				if !self.tx_page.complete(
					Completion::Transmit(sent),
					now_ns().saturating_add(TIMEOUT_NS),
				) || !self.tx.consumed_response(slot)
				{
					return Err(io());
				}
			}
		}
		if self.tx_page.revoking() {
			let revoked = self.table.revoke(TX_DATA_GRANT).map_err(|_| io())?;
			let _ = self.tx_page.reclaim(revoked);
		}
		ring.set_response_event(self.tx.event());
		fence(Ordering::SeqCst);
		if self.tx_page.expire(now_ns()) {
			return Err(-i32::from(Errno::Timedout));
		}
		Ok(())
	}

	/// Publish a copied outgoing frame. Busy is backpressure; ambiguous effects
	/// are errors and the outer adapter quarantines before another operation.
	fn transmit(&mut self, buffer: *const u8, bytes: usize) -> Result<(), i32> {
		let request = wire::tx_request(TX_DATA_GRANT, 0, bytes).ok_or(-i32::from(Errno::Inval))?;
		self.poll_transmit()?;
		if !self.tx_page.reusable() {
			return Err(-i32::from(Errno::Again));
		}
		let ring = unsafe { Ring::borrow((&raw mut TX_RING).cast::<u8>(), &self.life) }?;
		let slot = self
			.tx
			.request(ring.request_producer())
			.map_err(|_| io())?
			.ok_or_else(io)?;
		// Exclusive page ownership was checked before any CPU access. Caller
		// memory is valid only for this call and is never itself granted.
		unsafe {
			ptr::copy_nonoverlapping(buffer, (&raw mut TX_DATA).cast(), bytes);
		}
		if !self.tx_page.offer(now_ns().saturating_add(TIMEOUT_NS)) {
			return Err(io());
		}
		unsafe {
			self.table
				.grant(
					TX_DATA_GRANT,
					self.peer,
					(&raw mut TX_DATA).addr() as u64 >> 12,
				)
				.map_err(|_| io())?;
		}
		#[cfg(feature = "xen-net-selftest")]
		let request = {
			let mut request = request;
			if FAULT.load(Ordering::Acquire) == 1 {
				request[6] = 4;
			}
			request
		};
		ring.write(&slot, &request)?;
		let old = slot.current();
		let next = slot.published();
		if !self.tx.posted(slot) {
			return Err(io());
		}
		let published = next;
		#[cfg(feature = "xen-net-selftest")]
		let published = if FAULT.load(Ordering::Acquire) == 2 {
			next.wrapping_add(256)
		} else {
			next
		};
		ring.publish_request(published);
		self.notify(&ring, old, published)
	}

	/// Consume at most one RX descriptor. Completion stays in the loan object
	/// until revoke succeeds; only then may bounded offsets touch the data page.
	fn receive(&mut self, buffer: *mut u8) -> Result<usize, i32> {
		self.poll_transmit()?;
		let ring = unsafe { Ring::borrow((&raw mut RX_RING).cast::<u8>(), &self.life) }?;
		if self.rx_page.awaiting() {
			if let Some(slot) = ring.front_response(&self.rx)? {
				let bytes = ring.read::<8>(&slot)?;
				let received = wire::rx_response(&bytes, 0).map_err(|_| io())?;
				if !self.rx_page.complete(
					Completion::Receive(received),
					now_ns().saturating_add(TIMEOUT_NS),
				) || !self.rx.consumed_response(slot)
				{
					return Err(io());
				}
			}
		}
		let mut length = 0;
		if self.rx_page.revoking() {
			let revoked = self.table.revoke(RX_DATA_GRANT).map_err(|_| io())?;
			if let Some(Completion::Receive(Receive::Packet(frame))) = self.rx_page.reclaim(revoked)
			{
				length = frame.len();
				for index in 0..length {
					let offset = frame.byte(index).ok_or_else(io)?;
					unsafe {
						let byte =
							ptr::read_volatile((&raw const RX_DATA).cast::<u8>().add(offset));
						ptr::write(buffer.add(index), byte);
					}
				}
			}
		}
		if self.rx_page.expire(now_ns()) {
			return Err(-i32::from(Errno::Timedout));
		}
		ring.set_response_event(self.rx.event());
		fence(Ordering::SeqCst);
		self.post_receive()?;
		Ok(length)
	}
}

/// Connect vif/0 to the exact peer domain explicitly authorized by the caller.
/// No automatic discovery may broaden this selection; additional vifs are not
/// attached by this API. Reopen requires fully confirmed previous teardown.
/// Failed attempts retain their fixed pages until domain teardown.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_netfront_open(peer: u16) -> i32 {
	let _guard = match Guard::acquire() {
		Ok(value) => value,
		Err(error) => return error,
	};
	if !clock_ready() || !is_xen() {
		return -i32::from(Errno::Nosys);
	}
	if CLAIMED.swap(true, Ordering::AcqRel) {
		return -i32::from(Errno::Busy);
	}
	let result = (|| {
		let deadline = now_ns().saturating_add(TIMEOUT_NS);
		// A prior owner can reach this point only after confirmed revoke/unbind.
		// Clear complete pages before offering them to any newly selected peer.
		for page in [
			(&raw mut TX_RING).cast::<u8>(),
			(&raw mut RX_RING).cast::<u8>(),
			(&raw mut TX_DATA).cast::<u8>(),
			(&raw mut RX_DATA).cast::<u8>(),
		] {
			for offset in 0..4096 {
				unsafe {
					ptr::write_volatile(page.add(offset), 0);
				}
			}
		}
		let mut xs = Store::open()?;
		let own = xs.read("domid", deadline)?;
		let observed_peer = xs.read("device/vif/0/backend-id", deadline)?;
		if !wire::identity::domain_matches(observed_peer.as_bytes(), peer) {
			return Err(io());
		}
		let back = xs.read("device/vif/0/backend", deadline)?;
		let peer_digits = format!("{peer}");
		if !wire::identity::backend_linked(
			peer,
			peer_digits.as_bytes(),
			own.as_bytes(),
			back.as_bytes(),
		) {
			return Err(io());
		}
		let reciprocal = xs.read(&format!("{back}/frontend"), deadline)?;
		if !wire::identity::frontend_linked(own.as_bytes(), reciprocal.as_bytes()) {
			return Err(io());
		}
		xs.write("device/vif/0/state", "1", deadline)?;
		state(&mut xs, &back, State::InitWait, State::InitWait, deadline)?;
		if xs.read(&format!("{back}/feature-rx-copy"), deadline)? != "1" {
			return Err(io());
		}
		let table = super::grants::table().map_err(|_| io())?;
		let hyp = hypervisor();
		let port = RawEventChannelInterface::new(hyp)
			.alloc(xen_sys::DomId(peer))
			.map_err(|_| io())?;
		// Install the resource owner before any subsequent fallible effect.
		let mut life = Life::new();
		if !life.begin() {
			return Err(io());
		}
		unsafe {
			*DEVICE.device.get() = Some(Device {
				xs,
				back,
				peer: xen_sys::DomId(peer),
				table,
				port,
				life,
				tx: Front::tx(),
				rx: Front::rx(),
				tx_page: Page::new(Direction::Transmit),
				rx_page: Page::new(Direction::Receive),
			});
		}
		let device = unsafe { (&mut *DEVICE.device.get()).as_mut() }.ok_or_else(io)?;
		EVENTS.unmask(&hyp, port.0).map_err(|_| io())?;
		for (ring, grant) in [
			((&raw mut TX_RING).cast::<u8>(), TX_RING_GRANT),
			((&raw mut RX_RING).cast::<u8>(), RX_RING_GRANT),
		] {
			let view = unsafe { Ring::borrow(ring, &device.life) }?;
			view.set_request_event(1);
			view.set_response_event(1);
			unsafe {
				device
					.table
					.grant(grant, device.peer, ring.addr() as u64 >> 12)
					.map_err(|_| io())?;
			}
		}
		device.post_receive()?;
		device.xs.transaction(deadline, |scope| {
			for (key, value) in [
				("tx-ring-ref", format!("{TX_RING_GRANT}")),
				("rx-ring-ref", format!("{RX_RING_GRANT}")),
				("event-channel", format!("{port}", port = device.port.0)),
				("request-rx-copy", String::from("1")),
				("feature-rx-notify", String::from("1")),
				("feature-no-csum-offload", String::from("1")),
				("feature-ipv6-csum-offload", String::from("0")),
				("feature-sg", String::from("0")),
				("feature-gso-tcpv4", String::from("0")),
				("feature-gso-tcpv6", String::from("0")),
				("state", String::from("4")),
			] {
				scope.write(&format!("device/vif/0/{key}"), &value)?;
			}
			Ok(())
		})?;
		let peer_state = state(
			&mut device.xs,
			&device.back,
			State::Connected,
			State::Connected,
			deadline,
		)?;
		if !device.life.connected(peer_state.as_bytes(), true) {
			return Err(io());
		}
		println!("XEN_NETFRONT_READY peer={peer} queues=1 offloads=0");
		Ok(())
	})();
	if result.is_err() {
		if let Some(device) = unsafe { (&mut *DEVICE.device.get()).as_mut() } {
			device.fail();
		}
	}
	result.map_or_else(|error| error, |()| 0)
}

/// Copy one outgoing frame; -EAGAIN is nonblocking backpressure. Success means
/// accepted by this local interface, not acknowledged delivery by the backend.
/// # Safety
/// buffer addresses bytes readable bytes, remains valid for this entire call,
/// and does not alias the driver's private static pages.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sys_xen_netfront_send(buffer: *const u8, bytes: usize) -> i32 {
	let _guard = match Guard::acquire() {
		Ok(value) => value,
		Err(error) => return error,
	};
	if buffer.is_null() || bytes == 0 || bytes > wire::PAGE {
		return -i32::from(Errno::Inval);
	}
	let Some(device) = (unsafe { &mut *DEVICE.device.get() }).as_mut() else {
		return -i32::from(Errno::Nodev);
	};
	if !device.life.usable() {
		return io();
	}
	let result = device.transmit(buffer, bytes);
	if result
		.as_ref()
		.is_err_and(|error| *error != -i32::from(Errno::Again))
	{
		device.fail();
	}
	result.map_or_else(|error| error, |()| 0)
}

/// Poll bounded TX/RX progress and copy at most one incoming frame; zero means
/// no packet available yet. The caller must recheck after publishing its wait
/// generation to avoid missing an event; this call never sleeps for a peer.
/// # Safety
/// buffer addresses at least 4096 writable bytes for this entire call and does
/// not alias any driver's static pages.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sys_xen_netfront_poll(buffer: *mut u8, capacity: usize) -> i32 {
	let _guard = match Guard::acquire() {
		Ok(value) => value,
		Err(error) => return error,
	};
	if buffer.is_null() || capacity < wire::PAGE {
		return -i32::from(Errno::Inval);
	}
	let Some(device) = (unsafe { &mut *DEVICE.device.get() }).as_mut() else {
		return -i32::from(Errno::Nodev);
	};
	if !device.life.usable() {
		return io();
	}
	match device.receive(buffer) {
		Ok(length) => length as i32,
		Err(error) => {
			device.fail();
			error
		}
	}
}

/// Explicit bounded XenBus shutdown. New data operations stop before any I/O;
/// resources stay charged if protocol close, revoke or event release fails.
/// A failed cleanup is not replayed through this interface owner.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_netfront_close() -> i32 {
	let _guard = match Guard::acquire() {
		Ok(value) => value,
		Err(error) => return error,
	};
	let Some(device) = (unsafe { &mut *DEVICE.device.get() }).as_mut() else {
		return 0;
	};
	if !device.life.close() {
		return io();
	}
	let result = (|| {
		let deadline = now_ns().saturating_add(TIMEOUT_NS);
		device.xs.write("device/vif/0/state", "5", deadline)?;
		state(
			&mut device.xs,
			&device.back,
			State::Closing,
			State::Closed,
			deadline,
		)?;
		device.xs.write("device/vif/0/state", "6", deadline)?;
		state(
			&mut device.xs,
			&device.back,
			State::Closed,
			State::Closed,
			deadline,
		)?;
		for grant in [TX_DATA_GRANT, RX_DATA_GRANT, TX_RING_GRANT, RX_RING_GRANT] {
			loop {
				let observed = GENERATION.load(Ordering::SeqCst);
				if device.table.revoke(grant).map_err(|_| io())? {
					break;
				}
				if now_ns() >= deadline {
					return Err(-i32::from(Errno::Timedout));
				}
				// Grant release need not send a netif event. Bounded periodic
				// retries prevent sleeping indefinitely on that absent signal.
				let wake = now_ns().saturating_add(10_000_000).min(deadline);
				let result = super::wait_for_generation(observed, wake);
				if result != 0
					&& result != -i32::from(Errno::Again)
					&& result != -i32::from(Errno::Timedout)
				{
					return Err(result);
				}
			}
		}
		EVENTS.mask(device.port.0).map_err(|_| io())?;
		RawEventChannelInterface::new(hypervisor())
			.unbind(device.port)
			.map_err(|_| io())?;
		Ok(())
	})();
	let released = device.life.released(result.is_ok());
	if released {
		unsafe {
			*DEVICE.device.get() = None;
		}
		CLAIMED.store(false, Ordering::Release);
		println!("XEN_NETFRONT_RELEASED grants=0");
	} else {
		device.fail();
	}
	result.map_or_else(|error| error, |()| 0)
}

/// Deliberate hostile-peer fixture mutation, excluded from production kernels.
/// One adds an unnegotiated fragment flag; two overruns the ring producer. These
/// bodies intentionally violate the normal codec's contract and prove nothing
/// about production encoding; they exercise a remote backend's rejection path.
#[cfg(feature = "xen-net-selftest")]
static FAULT: AtomicU32 = AtomicU32::new(0);

/// Select one hostile fixture input before sending its single packet.
#[cfg(feature = "xen-net-selftest")]
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_netfront_fault(mode: u32) -> i32 {
	if mode != 1 && mode != 2 {
		return -i32::from(Errno::Inval);
	}
	FAULT.store(mode, Ordering::Release);
	0
}
