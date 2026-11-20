//! Hardware Abstraction Layer (HAL) scaffolding for Cisco RV180W.
//! Phase 1: map and control switch/VLAN/HW NAT, Atheros Wi-Fi, LEDs/reset/MAC, MTD.

pub mod board {
    /// Placeholder: LED, reset button, MAC/board identity access.
    pub fn status_summary() -> &'static str {
        "hal.board: scaffold"
    }
}

pub mod switch {
    /// Placeholder: bcm5398/VLAN/SPPE/HW NAT control.
    pub fn status_summary() -> &'static str {
        "hal.switch: scaffold"
    }
}

pub mod wifi {
    /// Placeholder: Atheros 802.11n (ath_*/wlan_*) control.
    pub fn status_summary() -> &'static str {
        "hal.wifi: scaffold"
    }
}
