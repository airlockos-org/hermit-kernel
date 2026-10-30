//! Exclusive XenStore connection for virtual-device negotiation.
//! Wire framing is shared with other Xen guests through rust-vmm/xen. The
//! runtime owns the mapped page, notifications, absolute deadlines and sleeping.
//!
//! Unverified boundary: Verus does not model this kernel's HVM hypercalls,
//! volatile cross-domain memory, atomic publication or scheduler wakeups. Their
//! correctness depends on Xen's PVH mapping, coherent x86-64 memory and the
//! existing event/timer implementation. CLAIMED enforces one owner for a fresh
//! domain; private shadow counters reject changes to frontend-owned indices.
//! The verified plan is used directly for every copied offset and publication
//! index. Acquire precedes copying; release follows copying. Rust's exclusive
//! borrows keep the same shadow counters and private buffers for the effect.
//! Notification failure and timeout propagate to the verified client's poisoned
//! state; the page/capability is retained until domain teardown, never reopened.
//! Block's operation guard prevents reentry; its rejecting watch sink is bounded.
//! These are explicit assumptions and checked correspondence, not a proof of
//! hypercalls, volatile I/O, interrupts or the scheduler. Real-Xen regressions
//! exercise this boundary but do not turn those assumptions into verified facts.

use alloc::format;
use alloc::string::String;
use core::ptr;
use core::sync::atomic::AtomicBool;

use xen::io::store::{Client, Error, Operation, Transport, ring};

use super::*;

/// Prevent independent drivers from consuming each other's replies. A future
/// multi-device owner must distribute mutable access to this single connection.
static CLAIMED: AtomicBool = AtomicBool::new(false);

/// Sole XenStore client for this domain lifetime; never reopened after failure.
pub(super) struct Store {
	/// Framing and request identity, poisoned on ambiguous exchange failure.
	client: Client,
	/// Xen-provided page, retained until the domain is destroyed.
	page: *mut u8,
	/// Daemon event channel, which is not closed as a device-owned channel.
	port: EventChannel,
	/// Private shadow of the frontend-owned request producer.
	request: u32,
	/// Private shadow of the frontend-owned response consumer.
	response: u32,
}

impl Store {
	/// Claim the connection before inspecting or consuming its shared indices.
	pub(super) fn open() -> Result<Self, i32> {
		CLAIMED
			.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
			.map_err(|_| -i32::from(Errno::Busy))?;
		let hyp = hypervisor();
		let frame = hyp.get_hvm_param(HVM_PARAM_STORE_PFN).map_err(|_| io())?;
		let port = hyp
			.get_hvm_param(HVM_PARAM_STORE_EVTCHN)
			.map_err(|_| io())?;
		let address = ring::page_address(frame).ok_or_else(io)?;
		let port = EventChannel(port.try_into().map_err(|_| io())?);
		EVENTS.unmask(&hyp, port.0).map_err(|_| io())?;
		let page = address as *mut u8;
		// SAFETY: Xen's HVM store PFN is a mapped, page-aligned shared page in
		// the PVH bootstrap's first 4 GiB. CLAIMED admits one owner for this
		// guest lifetime. These ABI index fields are aligned AtomicU32 words;
		// Xen and the guest use coherent x86-64 acquire/release publication.
		let load = |offset: usize| unsafe {
			AtomicU32::from_ptr(page.add(offset).cast()).load(Ordering::Acquire)
		};
		let request = load(2052);
		let response = load(2056);
		if !ring::fresh(request, load(2048), load(2060), response) {
			return Err(io());
		}
		Ok(Self {
			client: Client::new(),
			page,
			port,
			request,
			response,
		})
	}

	/// Exchange outside a transaction; block discovery does not register watches.
	pub(super) fn exchange(
		&mut self,
		kind: Operation,
		body: &[u8],
		deadline: u64,
	) -> Result<String, i32> {
		let mut ring = Ring {
			page: self.page,
			port: self.port,
			deadline,
			request: &mut self.request,
			response: &mut self.response,
		};
		let response = self
			.client
			.exchange(&mut ring, kind, 0, body, |_| false)
			.map_err(|error| match error {
				Error::Transport(code) => code,
				Error::TooLarge => -i32::from(Errno::Inval),
				Error::Daemon(name) if name == b"ENOENT" => -i32::from(Errno::Noent),
				_ => io(),
			})?;
		let length = xen::io::store::text_length(&response);
		let bytes = response.get(..length).ok_or_else(io)?;
		// UTF-8 validation and copying are standard-library trusted effects;
		// delimiter selection is performed by the verified core above.
		let text = core::str::from_utf8(bytes).map_err(|_| io())?;
		Ok(String::from(text))
	}

	/// Read a toolstack-provisioned device node within an absolute deadline.
	pub(super) fn read(&mut self, path: &str, deadline: u64) -> Result<String, i32> {
		self.exchange(Operation::Read, format!("{path}\0").as_bytes(), deadline)
	}

	/// Publish one device setting within an absolute deadline.
	pub(super) fn write(&mut self, path: &str, value: &str, deadline: u64) -> Result<(), i32> {
		self.exchange(
			Operation::Write,
			format!("{path}\0{value}").as_bytes(),
			deadline,
		)
		.map(|_| ())
	}
}

/// One bounded exchange borrowing the domain's mapped XenStore page.
struct Ring<'a> {
	/// Shared request/response ring page, never exposed as a Rust slice.
	page: *mut u8,
	/// Notification target for both producer and consumer progress.
	port: EventChannel,
	/// Absolute exchange deadline, including continuously progressing streams.
	deadline: u64,
	/// Exclusively borrowed local request producer, retained across exchanges.
	request: &'a mut u32,
	/// Exclusively borrowed local response consumer, retained across exchanges.
	response: &'a mut u32,
}

/// Common platform I/O failure.
fn io() -> i32 {
	-i32::from(Errno::Io)
}

impl Ring<'_> {
	/// Check time even when a peer keeps a stream continuously busy.
	fn check_deadline(&self) -> Result<(), i32> {
		if now_ns() >= self.deadline {
			Err(-i32::from(Errno::Timedout))
		} else {
			Ok(())
		}
	}

	/// Notify the daemon after shared indices are published.
	fn notify(&self) -> Result<(), i32> {
		RawEventChannelInterface::new(hypervisor())
			.send(self.port)
			.map_err(|_| io())
	}

	/// Sleep without losing a notification between observing indices and parking.
	fn wait(&self, observed: u32) -> Result<(), i32> {
		self.check_deadline()?;
		let result = wait_for_generation(observed, self.deadline);
		if result == 0 || result == -i32::from(Errno::Again) {
			Ok(())
		} else {
			Err(result)
		}
	}

	/// Acquire a peer-owned wrapping ring index.
	fn load(&self, offset: usize) -> u32 {
		// SAFETY: Calls use only aligned ABI fields 2048..2060 in the mapped
		// page retained by Store. No normal Rust reference aliases shared data.
		unsafe { AtomicU32::from_ptr(self.page.add(offset).cast()).load(Ordering::Acquire) }
	}

	/// Publish a locally owned index after copying the associated bytes.
	fn store(&self, offset: usize, value: u32) {
		// SAFETY: Calls publish only this frontend's aligned producer/consumer
		// fields. The matching private shadow is updated by the same owner.
		unsafe { AtomicU32::from_ptr(self.page.add(offset).cast()).store(value, Ordering::Release) }
	}
}

impl Transport for Ring<'_> {
	type Error = i32;

	fn write(&mut self, bytes: &[u8]) -> Result<usize, i32> {
		loop {
			self.check_deadline()?;
			let observed = GENERATION.load(Ordering::SeqCst);
			let plan = ring::send(*self.request, self.load(2052), self.load(2048), bytes.len())
				.ok_or_else(io)?;
			let size = plan.len();
			if size != 0 {
				for (index, byte) in bytes[..size].iter().enumerate() {
					let offset = plan.offset(index).ok_or_else(io)?;
					// SAFETY: The verified plan authorizes only offsets in the
					// request region. The private source slice is not shared.
					unsafe {
						ptr::write_volatile(self.page.add(offset), *byte);
					}
				}
				let next = plan.finish();
				self.store(2052, next);
				*self.request = next;
				self.notify()?;
				return Ok(size);
			}
			self.wait(observed)?;
		}
	}

	fn read(&mut self, bytes: &mut [u8]) -> Result<usize, i32> {
		loop {
			self.check_deadline()?;
			let observed = GENERATION.load(Ordering::SeqCst);
			let plan = ring::receive(
				*self.response,
				self.load(2056),
				self.load(2060),
				bytes.len(),
			)
			.ok_or_else(io)?;
			let size = plan.len();
			if size != 0 {
				for (index, byte) in bytes[..size].iter_mut().enumerate() {
					let offset = plan.offset(index).ok_or_else(io)?;
					// SAFETY: The verified plan authorizes response-region
					// offsets only. Each byte is copied into private memory;
					// no shared Rust slice/reference is exposed to the parser.
					*byte = unsafe { ptr::read_volatile(self.page.add(offset)) };
				}
				let next = plan.finish();
				self.store(2056, next);
				*self.response = next;
				self.notify()?;
				return Ok(size);
			}
			self.wait(observed)?;
		}
	}
}
