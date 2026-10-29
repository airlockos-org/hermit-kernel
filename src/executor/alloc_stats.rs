use core::sync::atomic::{AtomicU64, Ordering};

use crate::mm::ALLOCATOR;

/// Earliest next sample, in the scheduler clock's microseconds.
static NEXT_SAMPLE: AtomicU64 = AtomicU64::new(0);

/// Sample while the executor is already running, without introducing wakeups.
/// Values cover the shared kernel/application heap, not stacks or static pages.
/// The maximum in a log is a sampled maximum, not an allocation high-water mark.
pub(crate) fn sample() {
	let now = crate::arch::kernel::processor::get_timer_ticks();
	let next = NEXT_SAMPLE.load(Ordering::Relaxed);
	if now < next
		|| NEXT_SAMPLE
			.compare_exchange(
				next,
				now.saturating_add(1_000_000),
				Ordering::Relaxed,
				Ordering::Relaxed,
			)
			.is_err()
	{
		return;
	}

	// Never log while holding an allocator lock: formatting must remain free to
	// allocate, and physical/free heap snapshots need not hold both locks at once.
	let counters = *ALLOCATOR.lock().counters();
	let physical_free = crate::mm::FrameAlloc::free_bytes();

	info!(
		"HERMIT_MEMORY_STATS time_us={now} heap_live={} heap_free={} heap_reserved={} heap_overhead={} allocations={} physical_free={physical_free}",
		counters.allocated_bytes,
		counters.available_bytes,
		counters.claimed_bytes,
		counters.overhead_bytes(),
		counters.allocation_count,
	);
}
