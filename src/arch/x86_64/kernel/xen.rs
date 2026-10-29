//! Native Xen PVH platform glue. No emulated PC devices are required.
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use embedded_io::{ErrorType, Read, ReadReady, Write};
use xen::event::{EventChannel, EventChannelInterface, RawEventChannelInterface};
use xen::hypercall::hvm::XenHvmOp;
use xen::hypercall::sched::{ConsoleIO, SchedOp, console_io, sched_op};
use xen::io::XenConsInterface;
use xen::io::ring::XenRingError;
use xen_sys::bindings::*;
use xen_sys::{NativeXenHypercall, XenHypercall};

use crate::errno::Errno;

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

static CLOCK: xen::time::PvClock =
	unsafe { xen::time::PvClock::new((&raw const SHARED_INFO).cast()) };
static EVENTS: xen::event::two_level::TwoLevel =
	unsafe { xen::event::two_level::TwoLevel::new((&raw mut SHARED_INFO).cast()) };
static CLOCK_READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
pub fn clock_ready() -> bool {
	CLOCK_READY.load(Ordering::Acquire)
}
pub fn now_ns() -> u64 {
	CLOCK.now_ns().expect("Xen PV clock snapshot")
}
pub fn wallclock_micros() -> u64 {
	CLOCK.wallclock_ns().expect("Xen wallclock snapshot") / 1000
}
pub fn init_time() {
	let hyp = hypervisor();
	let ptr = (&raw mut SHARED_INFO).cast::<shared_info>();
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
			[XENMEM_add_to_physmap as _, (&raw mut map).addr()],
		)
		.expect("map shared info");
	}
	CLOCK_READY.store(true, Ordering::Release);
	println!("XEN_PVCLOCK_READY ns={}", now_ns());
}

const EVENT_VECTOR: u8 = 0xf3;
static TIMER_PORT: AtomicU32 = AtomicU32::new(0);
static TIMER_DEADLINE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static GENERATION: AtomicU32 = AtomicU32::new(0);
static EVENT_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static WAIT_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static TIMER_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn init_events() {
	unsafe {
		super::interrupts::IDT.lock()[EVENT_VECTOR]
			.set_handler_fn(event_handler)
			.set_stack_index(0);
	}
	super::interrupts::add_irq_name(EVENT_VECTOR - 32, "Xen events");
	let hyp = hypervisor();
	let port = RawEventChannelInterface::new(hyp)
		.bind_virq(VIRQ_TIMER, 0)
		.expect("bind Xen timer");
	TIMER_PORT.store(port.0, Ordering::Release);
	// public/vcpu.h VCPUOP_stop_periodic_timer=7, vCPU 0. No periodic idle ticks.
	unsafe {
		hyp.hypercall3(__HYPERVISOR_vcpu_op as _, [7, 0, 0])
			.expect("stop periodic Xen timer");
	}
	hyp.set_hvm_param(
		HVM_PARAM_CALLBACK_IRQ,
		(2u64 << 56) | u64::from(EVENT_VECTOR),
	)
	.expect("Xen callback vector");
	EVENTS.enable_upcalls();
	EVENTS.unmask(&hyp, port.0).expect("unmask Xen timer");
	println!("XEN_EVENTS_READY vector={EVENT_VECTOR} timer={}", port.0);
}
fn wake_waiters() {
	GENERATION.fetch_add(1, Ordering::SeqCst);
	crate::synch::futex::futex_wake(&GENERATION, i32::MAX);
}
extern "x86-interrupt" fn event_handler(_frame: super::interrupts::ExceptionStackFrame) {
	use crate::arch::kernel::core_local::{core_scheduler, increment_irq_counter};
	use crate::scheduler::PerCoreSchedulerExt;
	increment_irq_counter(EVENT_VECTOR);
	let mut timer = false;
	EVENTS.drain(|port| {
		EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
		if port == TIMER_PORT.load(Ordering::Acquire) {
			timer = true;
		}
	});
	if timer {
		let deadline = TIMER_DEADLINE.swap(0, Ordering::AcqRel);
		if deadline != 0 {
			if now_ns() / 1000 >= deadline {
				TIMER_COUNT.fetch_add(1, Ordering::Relaxed);
				crate::scheduler::timer_interrupts::clear_active_and_set_next();
				core_scheduler().handle_waiting_tasks();
			} else {
				set_timer(Some(deadline));
			}
		}
	}
	wake_waiters();
	super::apic::eoi();
	core_scheduler().reschedule();
}
pub fn set_timer(deadline: Option<u64>) {
	let value = deadline.unwrap_or(0);
	TIMER_DEADLINE.store(value, Ordering::Release);
	unsafe {
		hypervisor()
			.hypercall1(
				__HYPERVISOR_set_timer_op as _,
				value.saturating_mul(1000) as usize,
			)
			.expect("Xen single shot timer");
	}
}

/// Wait within an existing kernel entry; nesting exported syscalls would reset the kernel stack.
fn wait_for_generation(observed: u32, deadline_ns: u64) -> i32 {
	if now_ns() >= deadline_ns {
		return -i32::from(Errno::Timedout);
	}
	WAIT_COUNT.fetch_add(1, Ordering::Relaxed);
	hermit_sync::without_interrupts(|| {
		crate::scheduler::timer_interrupts::create_timer_abs(
			crate::scheduler::timer_interrupts::Source::XenWait,
			deadline_ns.div_ceil(1000),
		);
		// No futex timeout: the shared Xen timer wakes the generation futex.
		// This avoids a stale timeout waiter being woken a second time by an IRQ.
		let result = crate::synch::futex::futex_wait(
			&GENERATION,
			observed,
			None,
			crate::synch::futex::Flags::empty(),
		);
		crate::scheduler::timer_interrupts::cancel_xen_wait();
		if now_ns() >= deadline_ns {
			-i32::from(Errno::Timedout)
		} else {
			result
		}
	})
}
mod ipc;

mod connections;

mod block;

mod grants;
