use std::sync::Arc;

use bitflags::bitflags;
use tokio::sync::{futures::OwnedNotified, Notify};

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Event: u32 {
        const IN = 1;
        const OUT = 4;
    }
}

#[derive(Debug, Default)]
pub struct SocketData {
    readable: Arc<Notify>,
    writable: Arc<Notify>
}

#[derive(Debug, Default)]
pub struct RPoll {
    evts: scc::HashMap<super::Socket, SocketData>
}

impl RPoll {
    pub fn update_events(&self, socket: super::Socket, events: Event, value: bool) {
        let ent = self.evts.entry_sync(socket).or_default();
        if value {
            if events.contains(Event::IN) {
                ent.readable.notify_one();
            }
            if events.contains(Event::OUT) {
                ent.writable.notify_one();
            }
        }
    }

    pub(crate) fn update_events_cxx(&self, socket: super::Socket, events: u32, value: bool) {
        self.update_events(socket, Event::from_bits_retain(events), value);
    }

    pub(crate) fn remove_usock(&self, socket: super::Socket) {
        self.evts.remove_sync(&socket);
    }

    pub fn readable(&self, socket: super::Socket) -> Option<OwnedNotified> {
        self.evts.read_sync(&socket, |_, ent| ent.readable.clone().notified_owned())
    }

    pub fn writable(&self, socket: super::Socket) -> Option<OwnedNotified> {
        self.evts.read_sync(&socket, |_, ent| ent.writable.clone().notified_owned())
    }
}
