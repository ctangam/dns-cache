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

    pub fn prune(&mut self) -> usize {
        if self.current_size <= self.desired_size {
            return 0;
        }

        let mut pruned = self.remove_expired();

        while self.current_size > self.desired_size {
            pruned += self.remove_least_recently_used();
        }

        pruned
    }

    fn remove_least_recently_used(&mut self) -> usize {
        if let Some((name, _)) = self.access_priority.pop() {
            self.expiry_priority.remove(&name);

            if let Some(entry) = self.entries.remove(&name) {
                let pruned = entry.size;
                self.current_size -= pruned;
                pruned
            } else {
                0
            }
        } else {
            0
        }
    }

    fn remove_expired(&mut self) -> usize {
        let mut pruned = 0;
        
        loop {
            let before = pruned;
            pruned += self.remove_expired_step();
            if before == pruned {
                break;
            }
        }
        pruned
    }

    fn remove_expired_step(&mut self) -> usize {
        if let Some((name, Reverse(expiry))) = self.expiry_priority.pop() {
            let now = Instant::now();

            if expiry > now {
                self.expiry_priority.push(name, Reverse(expiry));
                return 0;
            }

            if let Some(entry) = self.entries.get_mut(&name) {
                let mut pruned = 0;

                let rtypes = entry.records.keys().cloned().collect::<Vec<_>>();
                let mut next_expiry = None;

                for rtype in rtypes {
                    if let Some(tuples) = entry.records.get_mut(&rtype) {
                        let len = tuples.len();
                        tuples.retain(|(_, _, expiry)| expiry > &now);
                        pruned += len - tuples.len();
                        for (_, _, expiry) in tuples {
                            match next_expiry {
                                None => next_expiry = Some(*expiry),
                                Some(t) if *expiry < t => next_expiry = Some(*expiry),
                                _ => (),
                            }
                        }
                    }
                }

                entry.size -= pruned;

                if let Some(ne) = next_expiry {
                    entry.next_expiry = ne;
                    self.expiry_priority.push(name, Reverse(ne));
                } else {
                    self.entries.remove(&name);
                    self.access_priority.remove(&name);
                }
                
                self.current_size -= pruned;
                pruned
            } else {
                self.access_priority.remove(&name);
                0
            }
        } else {
            0
        }
    }

}
