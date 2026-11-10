//! Minimal upstream-compatible subscription quota metadata.
//! Values are bytes (except Unix seconds for expire), not display strings.
use serde::{Deserialize,Serialize};

#[derive(Debug,Clone,Default,Serialize,Deserialize,PartialEq,Eq)]
pub struct SubscriptionInfo {
    #[serde(skip_serializing_if="Option::is_none")]
    pub upload:Option<u64>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub download:Option<u64>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub total:Option<u64>,
    #[serde(skip_serializing_if="Option::is_none")]
    pub expire:Option<u64>,
}
impl SubscriptionInfo {
    /// Ignore unknown fields and invalid numbers, never reflect arbitrary
    /// subscription server header bytes back into response headers.
    pub fn parse(header:&str)->Self {
        let mut result=Self::default();
        for part in header.split(';').take(16) {
            let Some((key,value))=part.trim().split_once('=') else {continue;};
            let Ok(number)=value.trim().parse::<u64>() else {continue;};
            match key.trim().to_ascii_lowercase().as_str() {
                "upload"=>result.upload=Some(number),
                "download"=>result.download=Some(number),
                "total"=>result.total=Some(number),
                "expire"=>result.expire=Some(number),
                _=>{}
            }
        }
        result
    }
    pub fn merge(&mut self,other:&Self) {
        fn sum(into:&mut Option<u64>,value:Option<u64>) {
            if let Some(v)=value {
                *into=Some(into.unwrap_or(0).saturating_add(v));
            }
        }
        sum(&mut self.upload,other.upload);
        sum(&mut self.download,other.download);
        sum(&mut self.total,other.total);
        if let Some(v)=other.expire {
            self.expire=Some(self.expire.map_or(v,|old|old.min(v)));
        }
    }
    pub fn header(&self)->Option<String> {
        let mut fields=Vec::new();
        for (name,value) in [
            ("upload",self.upload),("download",self.download),
            ("total",self.total),("expire",self.expire)
        ]{
            if let Some(v)=value {fields.push(format!("{name}={v}"));}
        }
        if fields.is_empty(){None}else{Some(fields.join("; "))}
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_and_merge_quota_metadata() {
        let first=SubscriptionInfo::parse("upload=1024; download=2048; total=8192; expire=1800000000");
        let second=SubscriptionInfo::parse("upload=512; download=2048; total=4096; expire=1750000000; other=99");
        let mut sum=first;
        sum.merge(&second);
        assert_eq!(sum.upload,Some(1536));
        assert_eq!(sum.download,Some(4096));
        assert_eq!(sum.total,Some(12288));
        assert_eq!(sum.expire,Some(1750000000));
        assert_eq!(sum.header().unwrap(),"upload=1536; download=4096; total=12288; expire=1750000000");
    }
    #[test]
    fn malformed_or_empty_quota_stays_empty() {
        assert_eq!(SubscriptionInfo::parse("download=-1;total=garbage;expire=NaN").header(),None);
        let mut merged=SubscriptionInfo::default();
        merged.merge(&SubscriptionInfo::parse("upload=18446744073709551615"));
        merged.merge(&SubscriptionInfo::parse("upload=200"));
        assert_eq!(merged.upload,Some(u64::MAX));
    }
}
