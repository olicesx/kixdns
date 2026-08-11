//! V2Ray .dat 文件的 protobuf 结构定义。
//!
//! 使用 Google 官方 protobuf 库 (prost) 解析,与 dae 的 pkg/geodata
//! (google.golang.org/protobuf) 对齐,替代手写 wire 解析。手写解析对
//! 字段顺序、未知字段、多字节 tag 的假设脆弱,任何 .dat 格式变体都会
//! 导致静默错位或错误网段。

use prost::Message;

/// GeoIPList:V2Ray .dat 顶层结构,`repeated GeoIP entry = 1`
#[derive(Clone, PartialEq, Message)]
pub struct GeoIPList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoIP>,
}

/// GeoIP:单个国家条目,`string country_code = 1; repeated CIDR cidr = 2`
#[derive(Clone, PartialEq, Message)]
pub struct GeoIP {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,
}

/// Cidr:`bytes ip = 1; uint32 prefix = 2`(ip 为 4 字节 IPv4 或 16 字节 IPv6)
#[derive(Clone, PartialEq, Message)]
pub struct Cidr {
    #[prost(bytes, tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}
