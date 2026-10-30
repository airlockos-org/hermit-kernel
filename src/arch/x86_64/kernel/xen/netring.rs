//! Shared native netif ring effects for frontend and backend adapters.
//! Queue/descriptor decisions execute the verified core. This module performs
//! only aligned atomic header access and volatile copies through checked Slot
//! offsets. It creates no Rust slice/reference into peer-owned mutable bytes.

use core::marker::PhantomData;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU32, Ordering, fence};

use xen::io::net::queue::{Back, Front, Slot};

use super::Errno;

/// Temporary ring view, bound to an immovable mapping/page owner's borrow. It
/// is neither Clone nor Send and cannot outlive that owner's borrow.
pub(super) struct Ring<'a> {
	/// One full page, valid for every effect throughout the owner borrow.
	base: NonNull<u8>,
	/// Prevent release/move of the borrowed owner while this view remains live.
	owner: PhantomData<&'a ()>,
}

impl<'a> Ring<'a> {
	/// Borrow one valid native netif page. Alignment/null checks are defensive;
	/// raw mapping lifetime and real queue correspondence remain caller duties.
	/// # Safety
	/// The entire page remains mapped/pinned while owner is borrowed; the caller
	/// serializes CPU access and uses the same queue/slot direction and instance.
	/// Foreign mutation follows the explicit Xen ABI/coherent-memory boundary,
	/// never Rust references. Do not unmap or release the backing page early.
	pub(super) unsafe fn borrow<T>(page: *mut u8, _owner: &'a T) -> Result<Self, i32> {
		if page.addr() % 4096 != 0 {
			return Err(-i32::from(Errno::Io));
		}
		let base = NonNull::new(page).ok_or(-i32::from(Errno::Io))?;
		Ok(Self {
			base,
			owner: PhantomData,
		})
	}

	/// Acquire one of the four fixed, aligned native ring header fields.
	fn load(&self, offset: usize) -> u32 {
		unsafe {
			AtomicU32::from_ptr(self.base.as_ptr().add(offset).cast()).load(Ordering::Acquire)
		}
	}

	/// Release-publish a native local counter after its matching byte copy.
	fn store(&self, offset: usize, value: u32) {
		unsafe {
			AtomicU32::from_ptr(self.base.as_ptr().add(offset).cast())
				.store(value, Ordering::Release);
		}
	}

	/// Frontend-owned request producer, checked against its private shadow.
	pub(super) fn request_producer(&self) -> u32 {
		self.load(0)
	}

	/// Backend-owned request event threshold, read after the publication barrier.
	pub(super) fn request_event(&self) -> u32 {
		self.load(4)
	}

	/// Backend-owned response producer, checked against its private shadow.
	pub(super) fn response_producer(&self) -> u32 {
		self.load(8)
	}

	/// Frontend-owned response event threshold, read after the publication barrier.
	pub(super) fn response_event(&self) -> u32 {
		self.load(12)
	}

	/// Publish one frontend request after its checked descriptor copy.
	pub(super) fn publish_request(&self, next: u32) {
		self.store(0, next);
	}

	/// Publish one backend response after its checked descriptor copy.
	pub(super) fn publish_response(&self, next: u32) {
		self.store(8, next);
	}

	/// Ask the frontend for its next request, before a full barrier/recheck.
	pub(super) fn set_request_event(&self, next: u32) {
		self.store(4, next);
	}

	/// Ask the backend for its next response, before a full barrier/recheck.
	pub(super) fn set_response_event(&self, next: u32) {
		self.store(12, next);
	}

	/// Snapshot one frontend response. Before reporting empty, publish the next
	/// event and recheck after a full barrier so a caller may use its generation
	/// guard for waiting. Both finite decisions execute the verified queue.
	pub(super) fn front_response(&self, queue: &Front) -> Result<Option<Slot>, i32> {
		let plan = queue
			.response(self.request_producer(), self.response_producer())
			.map_err(|_| -i32::from(Errno::Io))?;
		if plan.is_some() {
			return Ok(plan);
		}
		self.set_response_event(queue.event());
		fence(Ordering::SeqCst);
		queue
			.response(self.request_producer(), self.response_producer())
			.map_err(|_| -i32::from(Errno::Io))
	}

	/// Snapshot one backend request, publishing/rechecking the event threshold
	/// before reporting empty. No peer-controlled retry or waiting loop occurs.
	pub(super) fn back_request(&self, queue: &Back) -> Result<Option<Slot>, i32> {
		let plan = queue
			.request(self.response_producer(), self.request_producer())
			.map_err(|_| -i32::from(Errno::Io))?;
		if plan.is_some() {
			return Ok(plan);
		}
		self.set_request_event(queue.event());
		fence(Ordering::SeqCst);
		queue
			.request(self.response_producer(), self.request_producer())
			.map_err(|_| -i32::from(Errno::Io))
	}

	/// Copy an immutable native request/response through bounded slot offsets.
	pub(super) fn write<const N: usize>(&self, slot: &Slot, bytes: &[u8; N]) -> Result<(), i32> {
		if N > slot.len() {
			return Err(-i32::from(Errno::Io));
		}
		for (index, byte) in bytes.iter().enumerate() {
			let offset = slot.byte(index).ok_or(-i32::from(Errno::Io))?;
			unsafe {
				ptr::write_volatile(self.base.as_ptr().add(offset), *byte);
			}
		}
		Ok(())
	}

	/// Snapshot a hostile descriptor once into private fixed-size memory.
	pub(super) fn read<const N: usize>(&self, slot: &Slot) -> Result<[u8; N], i32> {
		if N > slot.len() {
			return Err(-i32::from(Errno::Io));
		}
		let mut bytes = [0; N];
		for (index, byte) in bytes.iter_mut().enumerate() {
			let offset = slot.byte(index).ok_or(-i32::from(Errno::Io))?;
			*byte = unsafe { ptr::read_volatile(self.base.as_ptr().add(offset)) };
		}
		Ok(bytes)
	}
}
