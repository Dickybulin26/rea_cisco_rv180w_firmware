use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    pub system: SystemConfig,
    pub network: NetworkConfig,
    pub dhcp_dns: DhcpDnsConfig,
    pub wifi: WifiConfig,
    pub firewall: FirewallConfig,
    pub qos: QosConfig,
    pub vpn: VpnConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            system: SystemConfig::default(),
            network: NetworkConfig::default(),
            dhcp_dns: DhcpDnsConfig::default(),
            wifi: WifiConfig::default(),
            firewall: FirewallConfig::default(),
            qos: QosConfig::default(),
            vpn: VpnConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SystemConfig {
    pub hostname: String,
    pub timezone: String,
    pub ntp_enabled: bool,
    pub ntp_servers: Vec<String>,
    pub remote_mgmt_wan: bool,
    pub ssh_enabled: bool,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            hostname: "RV180W".to_string(),
            timezone: "UTC".to_string(),
            ntp_enabled: true,
            ntp_servers: vec!["pool.ntp.org".to_string()],
            remote_mgmt_wan: false,
            ssh_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct NetworkConfig {
    pub wan: WanConfig,
    pub lan: LanConfig,
    pub vlans: Vec<VlanEntry>,
    pub static_routes: Vec<StaticRoute>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            wan: WanConfig::default(),
            lan: LanConfig::default(),
            vlans: Vec::new(),
            static_routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WanMode {
    Dhcp,
    Static,
    Pppoe,
}

impl Default for WanMode {
    fn default() -> Self {
        Self::Dhcp
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WanConfig {
    pub mode: WanMode,
    pub mac_clone: Option<String>,
    pub static_ip: Option<String>,
    pub static_netmask: Option<String>,
    pub static_gateway: Option<String>,
    pub pppoe_username: Option<String>,
    pub pppoe_password: Option<String>,
}

impl Default for WanConfig {
    fn default() -> Self {
        Self {
            mode: WanMode::Dhcp,
            mac_clone: None,
            static_ip: None,
            static_netmask: None,
            static_gateway: None,
            pppoe_username: None,
            pppoe_password: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LanConfig {
    pub ip: String,
    pub netmask: String,
}

impl Default for LanConfig {
    fn default() -> Self {
        Self {
            ip: "192.168.1.1".to_string(),
            netmask: "255.255.255.0".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct VlanEntry {
    pub id: u16,
    pub name: String,
    pub ports: Vec<String>,
    pub tagged: bool,
}

impl Default for VlanEntry {
    fn default() -> Self {
        Self {
            id: 1,
            name: "default".to_string(),
            ports: Vec::new(),
            tagged: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct StaticRoute {
    pub destination: String,
    pub netmask: String,
    pub gateway: String,
    pub metric: u32,
    pub interface: String,
}

impl Default for StaticRoute {
    fn default() -> Self {
        Self {
            destination: String::new(),
            netmask: String::new(),
            gateway: String::new(),
            metric: 0,
            interface: "wan".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DhcpDnsConfig {
    pub dhcp_enabled: bool,
    pub range_start: String,
    pub range_end: String,
    pub lease_time_minutes: u32,
    pub dns_servers: Vec<String>,
    pub local_domain: Option<String>,
}

impl Default for DhcpDnsConfig {
    fn default() -> Self {
        Self {
            dhcp_enabled: true,
            range_start: "192.168.1.100".to_string(),
            range_end: "192.168.1.200".to_string(),
            lease_time_minutes: 1440,
            dns_servers: Vec::new(),
            local_domain: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WifiConfig {
    pub enabled: bool,
    pub ssid: String,
    pub channel: u8,
    pub bandwidth_mhz: u8,
    pub country_code: String,
    pub security: WifiSecurity,
    pub guest_network: Option<GuestNetworkConfig>,
}

impl Default for WifiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ssid: "RV180W".to_string(),
            channel: 6,
            bandwidth_mhz: 20,
            country_code: "US".to_string(),
            security: WifiSecurity::default(),
            guest_network: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WifiAuthMode {
    Open,
    Wpa2Psk,
}

impl Default for WifiAuthMode {
    fn default() -> Self {
        Self::Wpa2Psk
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WifiSecurity {
    pub mode: WifiAuthMode,
    pub passphrase: Option<String>,
}

impl Default for WifiSecurity {
    fn default() -> Self {
        Self {
            mode: WifiAuthMode::Wpa2Psk,
            passphrase: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GuestNetworkConfig {
    pub enabled: bool,
    pub ssid: String,
    pub isolated: bool,
}

impl Default for GuestNetworkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ssid: "RV180W-Guest".to_string(),
            isolated: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FirewallConfig {
    pub default_wan_ingress_deny: bool,
    pub port_forwards: Vec<PortForwardRule>,
    pub access_rules: Vec<AccessRule>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            default_wan_ingress_deny: true,
            port_forwards: Vec::new(),
            access_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PortForwardRule {
    pub name: String,
    pub enabled: bool,
    pub proto: String,
    pub external_port: u16,
    pub internal_ip: String,
    pub internal_port: u16,
}

impl Default for PortForwardRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            proto: "tcp".to_string(),
            external_port: 0,
            internal_ip: String::new(),
            internal_port: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AccessRule {
    pub name: String,
    pub enabled: bool,
    pub action: String,
    pub src: String,
    pub dst: String,
}

impl Default for AccessRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            action: "deny".to_string(),
            src: String::new(),
            dst: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct QosConfig {
    pub enabled: bool,
}

impl Default for QosConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct VpnConfig {
    pub ipsec_enabled: bool,
    pub pptp_enabled: bool,
    pub l2tp_enabled: bool,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            ipsec_enabled: false,
            pptp_enabled: false,
            l2tp_enabled: false,
        }
    }
}
