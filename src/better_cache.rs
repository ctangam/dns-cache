use std::{cmp::Reverse, collections::HashMap, time::Instant};

use priority_queue::PriorityQueue;

use crate::dns::{DomainName, QueryClass, QueryType, RecordClass, RecordType, RecordTypeWithData, ResourceRecord};

#[derive(Debug)]
pub struct BetterCache {
    entries: HashMap<DomainName, CachedDomainRecords>,
    access_priority: PriorityQueue<DomainName, Reverse<Instant>>,
    expiry_priority: PriorityQueue<DomainName, Reverse<Instant>>,
    current_size: usize,
    desired_size: usize,
}

#[derive(Debug)]
pub struct CachedDomainRecords {
    last_read: Instant,
    next_expiry: Instant,
    size: usize,
    records: HashMap<RecordType, Vec<(RecordTypeWithData, RecordClass, Instant)>>,
}

impl BetterCache {
    pub fn new(desired_size: usize) -> Self {
        Self::with_desired_size(desired_size)
    }

    pub fn with_desired_size(desired_size: usize) -> Self {
        if desired_size == 0 {
            panic!("cannot create a zero-size cache");
        }
        Self {
            entries: HashMap::with_capacity(desired_size / 2),
            access_priority: PriorityQueue::with_capacity(desired_size),
            expiry_priority: PriorityQueue::with_capacity(desired_size),
            current_size: 0,
            desired_size,
        }
    }

    pub fn get(&mut self, name: &DomainName, qtype: &QueryType, qclass: &QueryClass) -> Vec<ResourceRecord> {
        let now = Instant::now();

        self.entries
            .get_mut(name)
            .map(|cached_domain_records| {
                let rrs: Vec<ResourceRecord> = match qtype {
                    QueryType::Wildcard => {
                        cached_domain_records
                            .records
                            .values()
                            .flatten()
                            .filter(|(_, rclass, _)| rclass.matches(qclass))
                            .map(|(rtype_with_data, rclass, expires)| ResourceRecord {
                                name: name.clone(),
                                rtype: rtype_with_data.clone(),
                                rclass: *rclass,
                                ttl: expires.saturating_duration_since(now),
                            })
                            .collect()
                    }
                    QueryType::Record(record_type) => {
                        cached_domain_records
                            .records
                            .get(record_type)
                            .into_iter()
                            .flatten()
                            .filter(|(_, rclass, _)| rclass.matches(qclass))
                            .map(|(rtype_with_data, rclass, expires)| ResourceRecord {
                                name: name.clone(),
                                rtype: rtype_with_data.clone(),
                                rclass: *rclass,
                                ttl: expires.saturating_duration_since(now),
                            })
                            .collect()
                    }
                };
                if !rrs.is_empty() {
                    cached_domain_records.last_read = now;
                    self.access_priority.change_priority(name, Reverse(now));
                }
                rrs
            })
            .unwrap_or_default()
    }
}
