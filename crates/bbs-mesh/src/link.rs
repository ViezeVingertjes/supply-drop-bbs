//! Backend selection for the mesh transport.
//!
//! A [`RadioLink`] is either a companion-frame connection (TCP, Pi HAT, or USB
//! serial to companion firmware) or a KISS Modem connection driven by the
//! in-process MeshCore node stack. Both produce the same
//! [`meshcore_companion::client::ClientEvent`] stream and accept
//! the same [`OutboundFrame`] commands, so the transport's event loop does not
//! know which one it is talking to.
//!
//! This is an enum rather than a trait object: the set of backends is closed,
//! and the event loop stays free of per-frame dynamic dispatch.

use meshcore_companion::client::{ClientEvent, CompanionClient};
use meshcore_companion::frame::OutboundFrame;
use meshcore_kiss::client::KissClient;
use tokio::sync::mpsc;

/// A connection to the radio, whichever protocol it speaks.
pub enum RadioLink {
    /// A companion-frame connection over TCP or USB serial.
    Companion(CompanionClient),
    /// A KISS Modem connection over USB serial.
    Kiss(KissClient),
}

impl RadioLink {
    /// A cloneable sender for pushing commands from outside the event loop.
    #[must_use]
    pub fn sender(&self) -> mpsc::Sender<OutboundFrame> {
        match self {
            Self::Companion(client) => client.sender(),
            Self::Kiss(client) => client.sender(),
        }
    }

    /// Receive the next event, or `None` once the worker has exited.
    pub async fn recv(&mut self) -> Option<ClientEvent> {
        match self {
            Self::Companion(client) => client.recv().await,
            Self::Kiss(client) => client.recv().await,
        }
    }
}
