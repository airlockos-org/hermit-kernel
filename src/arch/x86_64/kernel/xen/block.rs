//! One Xen PV block device, using a fixed ring and bounce page.
//! XenStore chooses the toolstack-provisioned device/backend; no emulated disk or
//! clipboard broker is involved. Failed or timed-out operations quarantine all
//! static pages until domain teardown. Reopening requires a fresh guest.

use alloc::format;
use alloc::string::String;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, fence};

use xen::grant::GrantTable;
use xen::io::block::{self as wire, Operation};

use super::store::Store;
use super::*;

// The endpoint ABI owns grants 8..72; this driver owns disjoint grant entries.
const RING_GRANT: u32 = 128;
const DATA_GRANT: u32 = 129;
const TIMEOUT_NS: u64 = 5_000_000_000;
static mut RING: SharedInfoPage = SharedInfoPage([0; 4096]);
static mut DATA: SharedInfoPage = SharedInfoPage([0; 4096]);

/// Exclusive operation ownership; concurrent callers fail instead of spinning.
static BUSY: AtomicBool = AtomicBool::new(false);
/// Once offered to a backend, these pages cannot be offered again in this boot.
static CLAIMED: AtomicBool = AtomicBool::new(false);

struct Owned(UnsafeCell<Option<Device>>);
// Only an OperationGuard may access this cell; IRQ handlers never access it.
unsafe impl Sync for Owned {}
static DEVICE: Owned = Owned(UnsafeCell::new(None));

struct OperationGuard;
impl OperationGuard {
	fn acquire() -> Result<Self, i32> {
		BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
			.map(|_| Self)
			.map_err(|_| -i32::from(Errno::Busy))
	}
}
impl Drop for OperationGuard {
	fn drop(&mut self) {
		BUSY.store(false, Ordering::Release);
	}
}

struct Device {
	/// Sole XenStore connection, preserved after errors for teardown only.
	xs: Store,
	/// Toolstack-owned frontend XenStore path.
	front: String,
	/// Toolstack-selected storage backend path.
	back: String,
	/// Identity of the only attached virtual block device.
	handle: u16,
	/// Block request notification port.
	port: EventChannel,
	/// Shared grant frame; entries outside this driver's range are untouched.
	table: GrantTable,
	/// Capacity in Xen ABI 512-byte sectors.
	sectors: u64,
	/// Backend advertises stable-cache flush support.
	flush: bool,
	/// Backend prohibits writes, independently of application policy.
	read_only: bool,
	/// Producer/consumer counter; precisely one request may be outstanding.
	index: u32,
	/// Monotonic request identity, distinct from the wrapping ring index.
	next: u64,
	/// Any ambiguous completion poisons further data operations.
	failed: bool,
}

fn io() -> i32 {
	-i32::from(Errno::Io)
}

fn load(page: *mut u8, offset: usize) -> u32 {
	unsafe { AtomicU32::from_ptr(page.add(offset).cast()).load(Ordering::Acquire) }
}

fn store(page: *mut u8, offset: usize, value: u32) {
	unsafe {
		AtomicU32::from_ptr(page.add(offset).cast()).store(value, Ordering::Release);
	}
}

fn notify(port: EventChannel) -> Result<(), i32> {
	RawEventChannelInterface::new(hypervisor())
		.send(port)
		.map_err(|_| io())
}

fn wait(observed: u32, deadline: u64) -> Result<(), i32> {
	if now_ns() >= deadline {
		return Err(-i32::from(Errno::Timedout));
	}
	let result = super::wait_for_generation(observed, deadline);
	if result == 0 || result == -i32::from(Errno::Again) {
		Ok(())
	} else {
		Err(result)
	}
}

fn state(xs: &mut Store, back: &str, wanted: &[&str], deadline: u64) -> Result<(), i32> {
	let mut watch = xs.watch(&format!("{back}/state"), deadline)?;
	loop {
		if wanted.contains(&watch.read(deadline)?.as_str()) {
			return watch.close(deadline);
		}
		watch.wait(deadline)?;
	}
}

impl Device {
	fn transfer(&mut self, op: Operation, sector: u64, bytes: usize) -> Result<(), i32> {
		if self.failed {
			return Err(io());
		}
		if op != Operation::Read && self.read_only {
			return Err(-i32::from(Errno::Rofs));
		}
		if op == Operation::Flush && !self.flush {
			return Err(-i32::from(Errno::Nosys));
		}
		let id = self.next;
		let request = wire::request(op, self.handle, id, sector, bytes, self.sectors, DATA_GRANT)
			.map_err(|_| -i32::from(Errno::Inval))?;
		self.next = id.checked_add(1).ok_or_else(io)?;
		// From publication onward, any failure must prohibit reuse of the buffer.
		self.failed = true;
		let ring = (&raw mut RING).cast::<u8>();
		let offset = wire::HEADER_BYTES + (self.index % wire::SLOTS) as usize * wire::SLOT_BYTES;
		for (index, byte) in request.iter().enumerate() {
			unsafe {
				ptr::write_volatile(ring.add(offset + index), *byte);
			}
		}
		store(ring, 0, self.index.wrapping_add(1));
		notify(self.port)?;
		let deadline = now_ns().saturating_add(TIMEOUT_NS);
		loop {
			let observed = GENERATION.load(Ordering::SeqCst);
			let count = load(ring, 8).wrapping_sub(self.index);
			if count > 1 {
				return Err(io());
			}
			if count == 1 {
				let mut response = [0; 16];
				for (index, byte) in response.iter_mut().enumerate() {
					*byte = unsafe { ptr::read_volatile(ring.add(offset + index)) };
				}
				wire::response(&response, id, op).map_err(|_| io())?;
				self.index = self.index.wrapping_add(1);
				store(ring, 12, self.index.wrapping_add(1));
				self.failed = false;
				return Ok(());
			}
			store(ring, 12, self.index.wrapping_add(1));
			fence(Ordering::SeqCst);
			if load(ring, 8) == self.index {
				wait(observed, deadline)?;
			}
		}
	}
}

/// Open the sole toolstack-provisioned VBD; capacity is returned separately.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_block_open() -> i32 {
	let _guard = match OperationGuard::acquire() {
		Ok(g) => g,
		Err(e) => return e,
	};
	if !clock_ready() || !is_xen() {
		return -i32::from(Errno::Nosys);
	}
	if CLAIMED.swap(true, Ordering::AcqRel) {
		return -i32::from(Errno::Busy);
	}
	let result = (|| {
		let deadline = now_ns().saturating_add(TIMEOUT_NS);
		#[cfg(feature = "xen-store-selftest")]
		super::store::selftest(deadline)?;
		let mut xs = Store::open()?;
		let entries = xs.exchange(
			xen::io::store::Operation::Directory,
			b"device/vbd\0",
			deadline,
		)?;
		let handle: u16 = entries.parse().map_err(|_| -i32::from(Errno::Inval))?;
		let front = format!("device/vbd/{handle}");
		let back = xs.read(&format!("{front}/backend"), deadline)?;
		if !back.starts_with("/local/domain/") || back.len() > 256 {
			return Err(io());
		}
		let peer: u16 = xs
			.read(&format!("{front}/backend-id"), deadline)?
			.parse()
			.map_err(|_| io())?;
		state(&mut xs, &back, &["2"], deadline)?;
		let hyp = hypervisor();
		let table = super::grants::table().map_err(|_| io())?;
		let port = RawEventChannelInterface::new(hyp)
			.alloc(xen_sys::DomId(peer))
			.map_err(|_| io())?;
		EVENTS.unmask(&hyp, port.0).map_err(|_| io())?;
		let ring = (&raw mut RING).cast::<u8>();
		store(ring, 4, 1);
		store(ring, 12, 1);
		// Install ownership before publishing grants so every failure quarantines pages.
		let device = Device {
			xs,
			front,
			back,
			handle,
			port,
			table,
			sectors: 0,
			flush: false,
			read_only: false,
			index: 0,
			next: 1,
			failed: true,
		};
		unsafe {
			*DEVICE.0.get() = Some(device);
		}
		let device = unsafe { (&mut *DEVICE.0.get()).as_mut().unwrap() };
		unsafe {
			device
				.table
				.grant(RING_GRANT, xen_sys::DomId(peer), ring.addr() as u64 >> 12)
				.map_err(|_| io())?;
			device
				.table
				.grant(
					DATA_GRANT,
					xen_sys::DomId(peer),
					(&raw mut DATA).addr() as u64 >> 12,
				)
				.map_err(|_| io())?;
		}
		let front = &device.front;
		device.xs.transaction(deadline, |scope| {
			for (key, value) in [
				("ring-ref", format!("{RING_GRANT}")),
				("event-channel", format!("{port}", port = device.port.0)),
				("protocol", String::from("x86_64-abi")),
				("feature-persistent", String::from("0")),
				("state", String::from("3")),
			] {
				scope.write(&format!("{front}/{key}"), &value)?;
			}
			Ok(())
		})?;
		state(&mut device.xs, &device.back, &["4"], deadline)?;
		if device
			.xs
			.read(&format!("{}/sector-size", device.back), deadline)?
			!= "512"
		{
			return Err(io());
		}
		device.sectors = device
			.xs
			.read(&format!("{}/sectors", device.back), deadline)?
			.parse()
			.map_err(|_| io())?;
		if device.sectors == 0 || device.sectors > u64::MAX / 512 {
			return Err(io());
		}
		let info: u32 = device
			.xs
			.read(&format!("{}/info", device.back), deadline)?
			.parse()
			.map_err(|_| io())?;
		device.read_only = info & 4 != 0;
		device.flush = match device
			.xs
			.read(&format!("{}/feature-flush-cache", device.back), deadline)
		{
			Ok(value) => value == "1",
			Err(e) if e == -i32::from(Errno::Noent) => false,
			Err(e) => return Err(e),
		};
		device
			.xs
			.write(&format!("{}/state", device.front), "4", deadline)?;
		device.failed = false;
		println!(
			"XEN_BLOCK_READY sectors={} read_only={} flush={}",
			device.sectors, device.read_only, device.flush
		);
		Ok(())
	})();
	result.map_or_else(|e| e, |()| 0)
}

/// Return capacity in sectors, or zero when unavailable.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_block_sectors() -> u64 {
	let Ok(_guard) = OperationGuard::acquire() else {
		return 0;
	};
	unsafe {
		(&*DEVICE.0.get())
			.as_ref()
			.filter(|d| !d.failed)
			.map_or(0, |d| d.sectors)
	}
}

/// Transfer at most one page through private copied buffers; no caller memory is granted.
/// The caller must supply a valid readable/writable buffer for the selected operation.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sys_xen_block_io(
	operation: u32,
	sector: u64,
	buffer: *mut u8,
	bytes: usize,
) -> i32 {
	let _guard = match OperationGuard::acquire() {
		Ok(g) => g,
		Err(e) => return e,
	};
	let op = match operation {
		0 => Operation::Read,
		1 => Operation::Write,
		3 => Operation::Flush,
		_ => return -i32::from(Errno::Inval),
	};
	if bytes > 4096 || (bytes != 0 && buffer.is_null()) {
		return -i32::from(Errno::Inval);
	}
	let Some(device) = (unsafe { &mut *DEVICE.0.get() }).as_mut() else {
		return -i32::from(Errno::Nodev);
	};
	if device.failed {
		return io();
	}
	if wire::request(
		op,
		device.handle,
		device.next,
		sector,
		bytes,
		device.sectors,
		DATA_GRANT,
	)
	.is_err()
	{
		return -i32::from(Errno::Inval);
	}
	if op == Operation::Write {
		unsafe {
			ptr::copy_nonoverlapping(buffer, (&raw mut DATA).cast(), bytes);
		}
	}
	let result = device.transfer(op, sector, bytes);
	if result.is_ok() && op == Operation::Read {
		unsafe {
			ptr::copy_nonoverlapping((&raw const DATA).cast(), buffer, bytes);
		}
	}
	// On ambiguous completion the backend may still own DATA; never reuse it.
	if !device.failed {
		for index in 0..4096 {
			unsafe {
				ptr::write_volatile((&raw mut DATA).cast::<u8>().add(index), 0);
			}
		}
	}
	result.map_or_else(|e| e, |()| 0)
}

/// Complete XenBus closure before withdrawing grants; busy pages remain pinned.
#[hermit_macro::system]
#[unsafe(no_mangle)]
pub extern "C" fn sys_xen_block_close() -> i32 {
	let _guard = match OperationGuard::acquire() {
		Ok(g) => g,
		Err(e) => return e,
	};
	let Some(device) = (unsafe { &mut *DEVICE.0.get() }).as_mut() else {
		return 0;
	};
	device.failed = true;
	let result = (|| {
		let deadline = now_ns().saturating_add(TIMEOUT_NS);
		device
			.xs
			.write(&format!("{}/state", device.front), "5", deadline)?;
		state(&mut device.xs, &device.back, &["5", "6"], deadline)?;
		device
			.xs
			.write(&format!("{}/state", device.front), "6", deadline)?;
		state(&mut device.xs, &device.back, &["6"], deadline)?;
		for grant in [DATA_GRANT, RING_GRANT] {
			loop {
				let observed = GENERATION.load(Ordering::SeqCst);
				if device.table.revoke(grant).map_err(|_| io())? {
					break;
				}
				wait(observed, deadline)?;
			}
		}
		EVENTS.mask(device.port.0).map_err(|_| io())?;
		RawEventChannelInterface::new(hypervisor())
			.unbind(device.port)
			.map_err(|_| io())?;
		Ok(())
	})();
	if result.is_ok() {
		unsafe {
			*DEVICE.0.get() = None;
		}
		println!("XEN_BLOCK_RELEASED grants=0");
	}
	result.map_or_else(|e| e, |()| 0)
}
