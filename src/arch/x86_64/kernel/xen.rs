//! Native Xen PVH platform glue. No emulated PC devices are required.
use crate::errno::Errno;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use embedded_io::{ErrorType, Read, ReadReady, Write};
use xen::event::{EventChannel, EventChannelInterface, RawEventChannelInterface};
use xen::hypercall::hvm::XenHvmOp;
use xen::hypercall::sched::{ConsoleIO, SchedOp, console_io, sched_op};
use xen::io::{XenConsInterface, ring::XenRingError};
use xen_sys::{NativeXenHypercall, XenHypercall, bindings::*};

static CONSOLE_ADDR: AtomicUsize = AtomicUsize::new(0);
static CONSOLE_PORT: AtomicU32 = AtomicU32::new(0);

pub fn is_xen() -> bool {
	unsafe { NativeXenHypercall::new().is_some() }
}
fn hypervisor() -> NativeXenHypercall {
	unsafe { NativeXenHypercall::new().expect("Xen CPUID missing") }
}

/// Called on the single boot CPU, before the allocator and normal console.
/// The PVH bootstrap maps the first 4 GiB, including Xen's reserved console frame.
pub fn early_init() {
	if !is_xen() {
		return;
	}
	let hyp = hypervisor();
	// This also makes Xen latch the 64-bit shared-info ABI. Direct native
	// hypercalls do not register a hypercall page, the other latching point.
	// Event reception remains disabled until a callback handler is implemented.
	hyp.set_hvm_param(HVM_PARAM_CALLBACK_IRQ, 0)
		.expect("Xen shared-info ABI");
	let mut message = *b"HERMIT_XEN_PVH_ENTRY\n";
	// Optional diagnostic copy to Xen's own log; the PV console is authoritative.
	let _ = console_io(&hyp, ConsoleIO::Write, &mut message);
	let pfn = hyp
		.get_hvm_param(HVM_PARAM_CONSOLE_PFN)
		.expect("Xen console PFN");
	let port = hyp
		.get_hvm_param(HVM_PARAM_CONSOLE_EVTCHN)
		.expect("Xen console event channel");
	assert!(
		pfn != 0 && pfn < (1 << 20),
		"console outside bootstrap mapping"
	);
	CONSOLE_PORT.store(port.try_into().unwrap(), Ordering::Relaxed);
	CONSOLE_ADDR.store((pfn as usize) << 12, Ordering::Release);
	Console.write_all(&message).unwrap();
}

pub struct Console;
impl ErrorType for Console {
	type Error = Errno;
}
impl Read for Console {
	fn read(&mut self, _: &mut [u8]) -> Result<usize, Errno> {
		Err(Errno::Again)
	}
}
impl ReadReady for Console {
	fn read_ready(&mut self) -> Result<bool, Errno> {
		Ok(false)
	}
}
impl Write for Console {
	fn write(&mut self, buf: &[u8]) -> Result<usize, Errno> {
		let ptr = NonNull::new(CONSOLE_ADDR.load(Ordering::Acquire) as *mut XenConsInterface)
			.ok_or(Errno::Io)?;
		// SAFETY: Xen supplied this mapped, page-aligned shared console frame.
		// Hermit's console lock serializes writers; early_init is single CPU.
		let mut ring = XenConsInterface::to_ring(unsafe { XenConsInterface::new(ptr) });
		let hyp = hypervisor();
		let events = RawEventChannelInterface::new(hyp);
		let port = EventChannel(CONSOLE_PORT.load(Ordering::Relaxed));
		for chunk in buf.chunks(1024) {
			let mut retries = 0;
			loop {
				match ring.write(chunk) {
					Ok(()) => break,
					Err(XenRingError::NotReady) if retries < 100_000 => {
						events.send(port).map_err(|_| Errno::Io)?;
						unsafe {
							sched_op(&hyp, SchedOp::r#yield, 0).map_err(|_| Errno::Io)?;
						}
						retries += 1;
					}
					_ => return Err(Errno::Io),
				}
			}
			events.send(port).map_err(|_| Errno::Io)?;
		}
		Ok(buf.len())
	}
	fn flush(&mut self) -> Result<(), Errno> {
		Ok(())
	}
}

pub fn shutdown(code: i32) -> ! {
	let _ = Console.write_all(b"HERMIT_XEN_SHUTDOWN\n");
	let reason = if code == 0 {
		SHUTDOWN_poweroff
	} else {
		SHUTDOWN_crash
	};
	// Xen consumes the reason synchronously and stops this domain.
	unsafe {
		sched_op(&hypervisor(), SchedOp::shutdown, reason).expect("Xen shutdown");
	}
	loop {
		core::hint::spin_loop();
	}
}

/// Xen CPUID leaf 3, subleaf 0 supplies the *guest* TSC frequency in kHz.
pub fn tsc_mhz() -> Option<u16> {
	let base = unsafe { xen_sys::x86_64::find_xen_leaves()? };
	let khz = unsafe { core::arch::x86_64::__cpuid_count(base + 3, 0).ecx };
	u16::try_from(khz / 1000).ok().filter(|f| *f != 0)
}

#[repr(C, align(4096))]
struct SharedInfoPage([u8; 4096]);
// A dedicated page in the kernel image: it is never part of the allocator.
static mut SHARED_INFO: SharedInfoPage = SharedInfoPage([0; 4096]);

pub fn wallclock_micros() -> u64 {
	use core::ptr::{addr_of, addr_of_mut, read_volatile};
	use core::sync::atomic::fence;
	let hyp = hypervisor();
	let ptr = (&raw mut SHARED_INFO).cast::<shared_info>();
	// The kernel image is identity mapped, and Xen replaces only this dedicated
	// page. Called once on the boot CPU before any other shared-info access.
	let mut map = xen_add_to_physmap {
		domid: xen_sys::DomId::SELF.0,
		size: 0,
		space: XENMAPSPACE_shared_info,
		idx: 0,
		gpfn: ptr.addr() as u64 >> 12,
	};
	unsafe {
		hyp.hypercall2(
			__HYPERVISOR_memory_op as _,
			[XENMEM_add_to_physmap as _, addr_of_mut!(map).addr()],
		)
		.expect("map Xen shared info");
		loop {
			let version = read_volatile(addr_of!((*ptr).wc_version));
			if version & 1 != 0 {
				core::hint::spin_loop();
				continue;
			}
			fence(Ordering::Acquire);
			let seconds = u64::from(read_volatile(addr_of!((*ptr).wc_sec)))
				| (u64::from(read_volatile(addr_of!((*ptr).wc_sec_hi))) << 32);
			let nanos = u64::from(read_volatile(addr_of!((*ptr).wc_nsec)));
			let now = hyp.get_time().expect("Xen time");
			fence(Ordering::Acquire);
			if version == read_volatile(addr_of!((*ptr).wc_version)) {
				return seconds * 1_000_000 + (nanos + now) / 1000;
			}
		}
	}
}
