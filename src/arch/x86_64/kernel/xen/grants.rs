//! Map the guest's single v1 grant frame exactly once across IPC and block I/O.
//! IPC owns entries 8..72; block owns 128..130; netfront owns 144..148. Remapping frame
//! zero into each subsystem's own address would invalidate earlier mappings.

use hermit_sync::InterruptTicketMutex;
use xen::grant::GrantTable;

use super::{SharedInfoPage, hypervisor};

static mut PAGE: SharedInfoPage = SharedInfoPage([0; 4096]);

struct Shared {
	/// Stable guest-wide mapping, retained for the entire domain lifetime.
	table: Option<GrantTable>,
}

// Only this interrupt mutex accesses initialization; copied views never move the page.
unsafe impl Send for Shared {}
static STATE: InterruptTicketMutex<Shared> = InterruptTicketMutex::new(Shared { table: None });

pub(super) fn table() -> Result<GrantTable, xen_sys::error::XenError> {
	let mut state = STATE.lock();
	if let Some(table) = state.table {
		return Ok(table);
	}
	let table = unsafe { GrantTable::initialize(&hypervisor(), (&raw mut PAGE).cast()) }?;
	state.table = Some(table);
	Ok(table)
}
