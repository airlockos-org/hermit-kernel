//! Exclusive XenStore connection for virtual-device negotiation.
//! Wire framing is shared with other Xen guests through rust-vmm/xen. The
//! runtime owns the mapped page, notifications, absolute deadlines and sleeping.
//!
//! Unverified boundary: Verus does not model this kernel's HVM hypercalls,
//! volatile cross-domain memory, atomic publication or scheduler wakeups. Their
//! correctness depends on Xen's PVH mapping, coherent x86-64 memory and the
//! existing event/timer implementation. The domain gate enforces one owner for a fresh
//! domain; private shadow counters reject observed changes to frontend-owned indices.
//! The verified plan is used directly for every copied offset and publication
//! index. Acquire precedes copying; release follows copying. Rust's exclusive
//! borrows keep the same shadow counters and private buffers for the effect.
//! Notification failure and timeout propagate to the verified client's poisoned
//! state; the page/capability is retained until domain teardown, never reopened.
//! The domain Access guard prevents reentry; its rejecting watch sink is bounded.
//! These are explicit assumptions and checked correspondence, not a proof of
//! hypercalls, volatile I/O, interrupts or the scheduler. State is volatile;
//! a failure after index publication or daemon mutation is an uncertain outcome,
//! not evidence that nothing changed. No request is replayed on this connection.
//! A matching XenStore reply is not a disk durability/flush acknowledgement.
//! Real-Xen regressions
//! exercise this boundary but do not turn those assumptions into verified facts.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::AtomicBool;

use xen::io::store::{Client, Error, Operation, Transport, domain, ring, transaction};

use super::*;

/// Nonblocking admission across sleeping XenStore operations. Never hold an
/// interrupt/spin mutex across an exchange: a waiter may need the scheduler.
static BUSY: AtomicBool = AtomicBool::new(false);

/// One domain-owned connection and its verified monotonic initialization state.
struct Shared {
	/// Gate is published ready only after connection installation under BUSY.
	gate: domain::Gate,
	/// Retained on stream failure; never reopened or reset in this guest boot.
	connection: Option<Connection>,
}

/// Raw storage accessible only through the uniquely acquired Access guard.
struct SharedCell {
	/// All mutable access is scoped to Access::state's exclusive borrow.
	value: UnsafeCell<Shared>,
}

// SAFETY: Access::acquire uses acquire/release atomic exclusion. No IRQ handler
// accesses this cell; references cannot outlive the guard, and reentry returns
// Busy. This is a platform synchronization boundary, not a Verus-verified atomic.
unsafe impl Sync for SharedCell {}

static DOMAIN: SharedCell = SharedCell {
	value: UnsafeCell::new(Shared {
		gate: domain::Gate::new(),
		connection: None,
	}),
};

/// Unique permission to borrow the domain state; not returned to device callers.
struct Access;

impl Access {
	/// Fail rather than spin if another caller is sleeping inside XenStore.
	fn acquire() -> Result<Self, i32> {
		BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
			.map(|_| Self)
			.map_err(|_| -i32::from(Errno::Busy))
	}

	/// Borrow shared state only for this uniquely acquired guard's lifetime.
	fn state(&mut self) -> &mut Shared {
		// SAFETY: No second Access exists while BUSY is true; the borrow of
		// this guard prevents releasing BUSY while the reference remains live.
		unsafe { &mut *DOMAIN.value.get() }
	}
}

impl Drop for Access {
	fn drop(&mut self) {
		BUSY.store(false, Ordering::Release);
	}
}

/// Serialize one bounded effect against the sole retained connection.
/// Lock order is driver operation guard, then Access; XenStore never calls a
/// driver while holding Access. Failed initialization is terminal, even if a
/// caller is interrupted between begin() and finish().
fn with_connection<T>(work: impl FnOnce(&mut Connection) -> Result<T, i32>) -> Result<T, i32> {
	let mut access = Access::acquire()?;
	let shared = access.state();
	if !shared.gate.usable() {
		if !shared.gate.begin() {
			return Err(io());
		}
		match Connection::open() {
			Ok(connection) => {
				shared.connection = Some(connection);
				if !shared.gate.finish(true) {
					return Err(io());
				}
			}
			Err(error) => {
				shared.gate.finish(false);
				return Err(error);
			}
		}
	}
	let Some(connection) = shared.connection.as_mut() else {
		shared.gate.poison();
		return Err(io());
	};
	if !connection.client.usable() {
		shared.gate.poison();
		return Err(io());
	}
	let result = work(connection);
	if !connection.client.usable() {
		shared.gate.poison();
	}
	result
}

/// Driver-local handle to the domain-owned connection. Closing/dropping a
/// device does not reset wire identities or revoke other drivers' access.
/// No connection, event channel or mapping is allocated per handle.
pub(super) struct Store {
	/// Kernel-local handle; the domain Access guard owns the actual exclusion.
	_local: core::marker::PhantomData<*mut ()>,
}

impl Store {
	/// Initialize the domain stream once or attach to its existing connection.
	pub(super) fn open() -> Result<Self, i32> {
		with_connection(|_| Ok(()))?;
		Ok(Self {
			_local: core::marker::PhantomData,
		})
	}

	/// Run one nontransactional request without giving a driver wire ownership.
	pub(super) fn exchange(
		&mut self,
		kind: Operation,
		body: &[u8],
		deadline: u64,
	) -> Result<String, i32> {
		with_connection(|connection| connection.exchange(kind, 0, body, deadline))
	}

	/// Run one bounded transaction while holding domain stream ownership.
	/// Commit is explicit after callback success; callback error triggers explicit
	/// abort. EAGAIN is returned for caller-directed recovery, never replayed.
	pub(super) fn transaction<T>(
		&mut self,
		deadline: u64,
		work: impl FnOnce(&mut Transaction<'_>) -> Result<T, i32>,
	) -> Result<T, i32> {
		with_connection(|connection| {
			let response = connection
				.raw(Operation::TransactionStart, 0, b"\0", deadline)
				.map_err(error_code)?;
			let Some(id) = transaction::Id::parse(&response) else {
				connection.client.poison();
				return Err(io());
			};
			let mut scope = Transaction {
				connection,
				id,
				deadline,
				finished: false,
			};
			let result = work(&mut scope);
			scope.finish(result.is_ok())?;
			result
		})
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

/// Borrowed transaction scope; cannot outlive or retarget its connection.
/// No Drop-based network cleanup: Store::transaction explicitly ends the scope
/// on both success and ordinary failure. Drop only quarantines an interrupted
/// scope; it never sends cleanup or permits replay of an uncertain transaction.
pub(super) struct Transaction<'a> {
	/// Same uniquely borrowed connection used to receive the transaction ID.
	connection: &'a mut Connection,
	/// Validated daemon identifier, bound to this consuming transaction scope.
	id: transaction::Id,
	/// One absolute deadline shared by start, all operations and completion.
	deadline: u64,
	/// True only after explicit completion or stream quarantine. Drop sends no
	/// I/O; an incomplete scope poisons the retained connection.
	finished: bool,
}

impl Transaction<'_> {
	/// Read using this scope's immutable transaction/connection binding.
	pub(super) fn read(&mut self, path: &str) -> Result<String, i32> {
		self.connection.exchange(
			Operation::Read,
			self.id.wire(),
			format!("{path}\0").as_bytes(),
			self.deadline,
		)
	}

	/// Write a setting invisible to outside readers until the commit succeeds.
	pub(super) fn write(&mut self, path: &str, value: &str) -> Result<(), i32> {
		self.connection
			.exchange(
				Operation::Write,
				self.id.wire(),
				format!("{path}\0{value}").as_bytes(),
				self.deadline,
			)
			.map(|_| ())
	}

	/// Consume the scope before sending one end request. Any unexpected outcome
	/// quarantines the stream; only a valid daemon conflict permits later work.
	fn finish(mut self, commit: bool) -> Result<(), i32> {
		let (id, body) = self.id.finish(commit);
		let result = match self
			.connection
			.raw(Operation::TransactionEnd, id, &body, self.deadline)
		{
			Ok(response) if transaction::acknowledged(&response) => Ok(()),
			Err(Error::Daemon(name)) if commit && name == b"EAGAIN" => {
				Err(-i32::from(Errno::Again))
			}
			_ => {
				self.connection.client.poison();
				Err(io())
			}
		};
		self.finished = true;
		result
	}
}

impl Drop for Transaction<'_> {
	fn drop(&mut self) {
		// Explicit finish performs fallible protocol cleanup. Drop only retains
		// uncertainty after an interrupted scope, without sending any request.
		if !self.finished {
			self.connection.client.poison();
		}
	}
}

/// Translate explicit wire failures to the existing kernel ABI. No error
/// translation creates successful completion or resets a poisoned client.
fn error_code(error: Error<i32>) -> i32 {
	match error {
		Error::Transport(code) => code,
		Error::TooLarge => -i32::from(Errno::Inval),
		Error::Daemon(name) if name == b"ENOENT" => -i32::from(Errno::Noent),
		_ => io(),
	}
}

/// Sole XenStore client for this domain lifetime; never reopened after failure.
struct Connection {
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

impl Connection {
	/// Claim the connection before inspecting or consuming its shared indices.
	fn open() -> Result<Self, i32> {
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
		// the PVH bootstrap's first 4 GiB. The domain gate admits one owner for this
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

	/// Keep raw typed errors for transaction completion decisions.
	fn raw(
		&mut self,
		kind: Operation,
		transaction: u32,
		body: &[u8],
		deadline: u64,
	) -> Result<Vec<u8>, Error<i32>> {
		let mut ring = Ring {
			page: self.page,
			port: self.port,
			deadline,
			request: &mut self.request,
			response: &mut self.response,
		};
		self.client
			.exchange(&mut ring, kind, transaction, body, |_| false)
	}

	/// Interpret a successful byte reply through the verified delimiter choice.
	fn exchange(
		&mut self,
		kind: Operation,
		transaction: u32,
		body: &[u8],
		deadline: u64,
	) -> Result<String, i32> {
		let response = self
			.raw(kind, transaction, body, deadline)
			.map_err(error_code)?;
		let length = xen::io::store::text_length(&response);
		let bytes = response.get(..length).ok_or_else(io)?;
		// UTF-8 validation/copying are trusted standard-library effects.
		let text = core::str::from_utf8(bytes).map_err(|_| io())?;
		Ok(String::from(text))
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

/// Exercise two independent device handles and nonblocking reentry in a lab
/// build. No diagnostic request path or selftest is compiled into normal VMs.
#[cfg(feature = "xen-store-selftest")]
pub(super) fn selftest(deadline: u64) -> Result<(), i32> {
	let mut first = Store::open()?;
	let mut second = Store::open()?;
	let identity = first.read("domid", deadline)?;
	if identity.is_empty() || second.read("domid", deadline)? != identity {
		return Err(io());
	}
	with_connection(|_| {
		if !matches!(Store::open(), Err(error) if error == -i32::from(Errno::Busy)) {
			return Err(io());
		}
		Ok(())
	})?;
	drop(first);
	let mut third = Store::open()?;
	if second.read("domid", deadline)? != identity || third.read("domid", deadline)? != identity {
		return Err(io());
	}
	let key = "data/hermit-xen-transaction";
	second.write(key, "before", deadline)?;
	let rejected: Result<(), i32> = second.transaction(deadline, |scope| {
		scope.write(key, "aborted")?;
		Err(-i32::from(Errno::Inval))
	});
	if rejected != Err(-i32::from(Errno::Inval)) || third.read(key, deadline)? != "before" {
		return Err(io());
	}
	second.transaction(deadline, |scope| {
		scope.write(key, "committed")?;
		if scope.read(key)? != "committed" {
			return Err(io());
		}
		Ok(())
	})?;
	if third.read(key, deadline)? != "committed" {
		return Err(io());
	}
	println!("XENSTORE_TRANSACTION_PASS");
	println!("XENSTORE_SHARED_PASS");
	Ok(())
}
