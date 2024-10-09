use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct ResourceRecord {
    pub name: DomainName,
    pub rtype: RecordTypeWithData,
    pub rclass: RecordClass,
    pub ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName {
    pub labels: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordTypeWithData {
    A { address: Ipv4Addr },
    CNAME { cname: DomainName },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    CNAME,
}

impl RecordTypeWithData {
    pub fn rtype(&self) -> RecordType {
        match self {
            RecordTypeWithData::A { .. } => RecordType::A,
            RecordTypeWithData::CNAME { .. } => RecordType::CNAME,
            // many more omitted
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClass {
    IN,
}

#[derive(Debug, Clone, Copy)]
pub enum QueryType {
    Record(RecordType),
    Wildcard,
}

impl RecordType {
    pub fn matches(&self, qtype: &QueryType) -> bool {
        match qtype {
            QueryType::Wildcard => true,
            QueryType::Record(rtype) => self == rtype,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum QueryClass {
    Record(RecordClass),
    Wildcard,
}

impl RecordClass {
    pub fn matches(&self, qclass: &QueryClass) -> bool {
        match qclass {
            QueryClass::Wildcard => true,
            QueryClass::Record(rclass) => self == rclass,
        }
    }
}