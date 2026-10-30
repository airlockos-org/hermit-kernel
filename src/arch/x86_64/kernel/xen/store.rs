//! Exclusive XenStore connection for virtual-device negotiation.
//! Wire framing is shared with other Xen guests through rust-vmm/xen. The
//! runtime owns the mapped page, notifications, absolute deadlines and sleeping.

use alloc::format;
use alloc::string::String;
use core::ptr;
use core::sync::atomic::AtomicBool;

use xen::io::store::{Client, Error, Operation, Transport};

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
		if frame == 0 || frame >= 1 << 20 {
			return Err(io());
		}
		let port = EventChannel(port.try_into().map_err(|_| io())?);
		EVENTS.unmask(&hyp, port.0).map_err(|_| io())?;
		Ok(Self {
			client: Client::new(),
			page: ((frame as usize) << 12) as *mut u8,
			port,
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
		let text = core::str::from_utf8(&response).map_err(|_| io())?;
		Ok(String::from(text.trim_end_matches('\0')))
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
struct Ring {
	/// Shared request/response ring page, never exposed as a Rust slice.
	page: *mut u8,
	/// Notification target for both producer and consumer progress.
	port: EventChannel,
	/// Absolute exchange deadline, including continuously progressing streams.
	deadline: u64,
}

/// Common platform I/O failure.
fn io() -> i32 {
	-i32::from(Errno::Io)
}

impl Ring {
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
		unsafe { AtomicU32::from_ptr(self.page.add(offset).cast()).load(Ordering::Acquire) }
	}

	/// Publish a locally owned index after copying the associated bytes.
	fn store(&self, offset: usize, value: u32) {
		unsafe { AtomicU32::from_ptr(self.page.add(offset).cast()).store(value, Ordering::Release) }
	}
}

impl Transport for Ring {
	type Error = i32;

	fn write(&mut self, bytes: &[u8]) -> Result<usize, i32> {
		loop {
			self.check_deadline()?;
			let observed = GENERATION.load(Ordering::SeqCst);
			let prod = self.load(2052);
			let queued = prod.wrapping_sub(self.load(2048)) as usize;
			if queued > 1024 {
				return Err(io());
			}
			let size = bytes.len().min(1024 - queued);
			if size != 0 {
				for (index, byte) in bytes[..size].iter().enumerate() {
					unsafe {
						ptr::write_volatile(self.page.add((prod as usize + index) % 1024), *byte);
					}
				}
				self.store(2052, prod.wrapping_add(size as u32));
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
			let cons = self.load(2056);
			let available = self.load(2060).wrapping_sub(cons) as usize;
			if available > 1024 {
				return Err(io());
			}
			let size = bytes.len().min(available);
			if size != 0 {
				for (index, byte) in bytes[..size].iter_mut().enumerate() {
					*byte = unsafe {
						ptr::read_volatile(self.page.add(1024 + (cons as usize + index) % 1024))
					};
				}
				self.store(2056, cons.wrapping_add(size as u32));
				self.notify()?;
				return Ok(size);
			}
			self.wait(observed)?;
		}
	}
}
