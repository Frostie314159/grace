use std::collections::HashMap;

use awdl_frame_parser::{
    common::{AWDLDnsCompression, AWDLDnsName, AWDLStr, ReadLabelIterator},
    tlvs::dns_sd::{dns_record::AWDLDnsRecord, ServiceResponseTLV},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SRVRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TXTRecord {
    pub txt_record: HashMap<String, String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AWDLService {
    pub name: String,
    pub ptr_name: String,
    pub domain: AWDLDnsCompression,
    pub srv: Option<SRVRecord>,
    pub txt: Option<TXTRecord>,
}
impl AWDLService {
    pub fn from_responses<'a>(
        responses: Vec<ServiceResponseTLV<'a, ReadLabelIterator<'a>>>,
    ) -> Vec<AWDLService> {
        let mut services = HashMap::new();
        responses.iter().for_each(|x| {
            if let AWDLDnsRecord::PTR { ref domain_name } = x.record {
                let name = AWDLDnsName {
                    domain: x.name.domain,
                    labels: domain_name.labels.chain(x.name.labels).collect::<Vec<_>>(),
                };
                services.insert(
                    name.clone(),
                    AWDLService {
                        name: name.to_string(),
                        ptr_name: domain_name
                            .labels
                            .clone()
                            .nth(0)
                            .unwrap_or(AWDLStr(""))
                            .to_string(),
                        domain: x.name.domain,
                        srv: None,
                        txt: None,
                    },
                );
            }
        });
        responses.iter().for_each(|x| {
            let Some(service) = services.get_mut(&AWDLDnsName {
                labels: x.name.labels.collect(),
                domain: x.name.domain,
            }) else {
                return;
            };
            match x.record {
                AWDLDnsRecord::SRV {
                    priority,
                    weight,
                    port,
                    ref target,
                } => {
                    service.srv = Some(SRVRecord {
                        priority,
                        weight,
                        port,
                        target: target.to_string(),
                    });
                }
                AWDLDnsRecord::TXT { ref txt_record } => {
                    service.txt = Some(TXTRecord {
                        txt_record: txt_record
                            .map_while(|x| x.split_once('='))
                            .map(|(key, value)| (key.to_string(), value.to_string()))
                            .collect(),
                    });
                }
                _ => {}
            }
        });
        services.values().cloned().collect()
    }
}
