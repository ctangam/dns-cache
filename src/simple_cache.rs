use std::{collections::HashMap, time::Instant};

use crate::dns::{DomainName, QueryClass, QueryType, RecordClass, RecordTypeWithData, ResourceRecord};

pub struct SimpleCache {
    entries: HashMap<DomainName, Vec<(RecordTypeWithData, RecordClass, Instant)>>,
}

impl SimpleCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: &DomainName, rr: ResourceRecord) {
        self.entries
            .entry(name.clone())
            .or_insert_with(Vec::new)
            .push((rr.rtype, rr.rclass, Instant::now() + rr.ttl));
    }

    pub fn get(&self, name: &DomainName, qtype: QueryType, qclass: QueryClass) -> Vec<ResourceRecord> {
        self.entries
            .get(name)
            .into_iter()
            .flatten()
            .filter(|(rtype_with_data, rclass, _)| rtype_with_data.rtype().matches(&qtype) && rclass.matches(&qclass))
            .map(|(rtype, rclass, expires)| ResourceRecord {
                name: name.clone(),
                rtype: rtype.clone(),
                rclass: *rclass,
                ttl: expires.saturating_duration_since(Instant::now()),
            })
            .collect()
    }
}

