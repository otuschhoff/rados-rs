use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use super::{Fsid, MapError, MonMap, OSDMap, Result};

#[derive(Clone, Debug)]
pub(crate) struct MapSnapshot {
    pub(crate) monmap: Arc<MonMap>,
    pub(crate) osdmap: Arc<OSDMap>,
}

impl MapSnapshot {
    pub(crate) fn new(monmap: Arc<MonMap>, osdmap: Arc<OSDMap>) -> Result<Self> {
        if monmap.fsid() != osdmap.fsid() {
            return Err(MapError::FsidMismatch);
        }
        Ok(Self { monmap, osdmap })
    }

    pub(crate) fn fsid(&self) -> Fsid {
        self.osdmap.fsid()
    }
}

#[derive(Debug)]
struct PublishedMaps {
    current: Arc<MapSnapshot>,
    history: VecDeque<Arc<MapSnapshot>>,
}

#[derive(Debug)]
pub(crate) struct MapStore {
    history_limit: usize,
    published: RwLock<PublishedMaps>,
}

impl MapStore {
    pub(crate) fn new(initial: MapSnapshot, history_limit: usize) -> Self {
        Self {
            history_limit,
            published: RwLock::new(PublishedMaps {
                current: Arc::new(initial),
                history: VecDeque::new(),
            }),
        }
    }

    pub(crate) fn load(&self) -> Result<Arc<MapSnapshot>> {
        Ok(Arc::clone(
            &self
                .published
                .read()
                .map_err(|_| MapError::LockPoisoned)?
                .current,
        ))
    }

    pub(crate) fn publish(&self, next: MapSnapshot) -> Result<Arc<MapSnapshot>> {
        let mut published = self.published.write().map_err(|_| MapError::LockPoisoned)?;
        if next.fsid() != published.current.fsid() {
            return Err(MapError::FsidMismatch);
        }
        if next.osdmap.epoch() <= published.current.osdmap.epoch()
            || next.monmap.epoch() < published.current.monmap.epoch()
        {
            return Err(MapError::InvalidSequence);
        }
        let next = Arc::new(next);
        let previous = std::mem::replace(&mut published.current, Arc::clone(&next));
        if self.history_limit != 0 {
            published.history.push_front(previous);
            published.history.truncate(self.history_limit);
        }
        Ok(next)
    }

    pub(crate) fn history(&self) -> Result<Vec<Arc<MapSnapshot>>> {
        Ok(self
            .published
            .read()
            .map_err(|_| MapError::LockPoisoned)?
            .history
            .iter()
            .cloned()
            .collect())
    }
}
