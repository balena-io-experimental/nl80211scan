mod enums;

#[allow(dead_code, non_upper_case_globals, non_camel_case_types)]
mod consts;

use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::hash::Hash;

use macaddr::MacAddr6;

use neli::attr::Attribute;
use neli::consts::nl::{NlmF, NlmFFlags, Nlmsg};
use neli::consts::socket::NlFamily;
use neli::genl::{Genlmsghdr, Nlattr};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::NlSocketHandle;
use neli::types::{Buffer, GenlBuffer, NlBuffer};

use enums::{Nl80211Attr, Nl80211Cmd};

const NL80211_FAMILY_NAME: &str = "nl80211";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterfaceType {
    Unspecified = 0,
    Adhoc,
    Station,
    AP,
    APVlan,
    WDS,
    Monitor,
    MeshPoint,
    P2PClient,
    P2PGo,
    P2PDevice,
    Ocb,
    Nan,
}

impl From<::std::os::raw::c_uint> for InterfaceType {
    fn from(orig: ::std::os::raw::c_uint) -> Self {
        match orig {
            consts::NL80211_IFTYPE_UNSPECIFIED => InterfaceType::Unspecified,
            consts::NL80211_IFTYPE_ADHOC => InterfaceType::Adhoc,
            consts::NL80211_IFTYPE_STATION => InterfaceType::Station,
            consts::NL80211_IFTYPE_AP => InterfaceType::AP,
            consts::NL80211_IFTYPE_AP_VLAN => InterfaceType::APVlan,
            consts::NL80211_IFTYPE_WDS => InterfaceType::WDS,
            consts::NL80211_IFTYPE_MONITOR => InterfaceType::Monitor,
            consts::NL80211_IFTYPE_MESH_POINT => InterfaceType::MeshPoint,
            consts::NL80211_IFTYPE_P2P_CLIENT => InterfaceType::P2PClient,
            consts::NL80211_IFTYPE_P2P_GO => InterfaceType::P2PGo,
            consts::NL80211_IFTYPE_P2P_DEVICE => InterfaceType::P2PDevice,
            consts::NL80211_IFTYPE_OCB => InterfaceType::Ocb,
            consts::NL80211_IFTYPE_NAN => InterfaceType::Nan,
            _ => return InterfaceType::Unspecified,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Interface {
    name: String,
    index: u32,
    interface_type: InterfaceType,
    wiphy: u32,
    wdev: u64,
    mac_address: MacAddr6,
}

impl Hash for Interface {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.mac_address.hash(state);
    }
}

impl PartialEq for Interface {
    fn eq(&self, other: &Self) -> bool {
        self.mac_address == other.mac_address
    }
}

impl Eq for Interface {}

impl TryFrom<&[Nlattr<Nl80211Attr, Buffer>]> for Interface {
    type Error = ();

    fn try_from(iface_attrs: &[Nlattr<Nl80211Attr, Buffer>]) -> Result<Self, Self::Error> {
        let iface_attrs: HashMap<_, _> = iface_attrs
            .iter()
            .map(|attr| (attr.nla_type.nla_type, attr))
            .collect();

        Ok(Interface {
            name: iface_attrs
                .get(&Nl80211Attr::Ifname)
                .and_then(|attr| attr.payload().as_ref().split_last())
                .and_then(|(_, name_bytes)| String::from_utf8(name_bytes.to_vec()).ok())
                .ok_or(())?,
            index: iface_attrs
                .get(&Nl80211Attr::Ifindex)
                .and_then(|attr| attr.get_payload_as().ok())
                .ok_or(())?,
            interface_type: iface_attrs
                .get(&Nl80211Attr::Iftype)
                .and_then(|attr| attr.get_payload_as().ok())
                .and_then(|if_type: u32| InterfaceType::try_from(if_type).ok())
                .ok_or(())?,
            wiphy: iface_attrs
                .get(&Nl80211Attr::Wiphy)
                .and_then(|attr| attr.get_payload_as().ok())
                .ok_or(())?,
            wdev: iface_attrs
                .get(&Nl80211Attr::Wdev)
                .and_then(|attr| attr.get_payload_as().ok())
                .ok_or(())?,
            mac_address: iface_attrs
                .get(&Nl80211Attr::Mac)
                .and_then(|attr| attr.payload().as_ref().try_into().ok())
                .map(|mac_bytes: [u8; 6]| MacAddr6::from(mac_bytes))
                .ok_or(())?,
        })
    }
}

pub fn scan() {
    let mut socket = NlSocketHandle::connect(NlFamily::Generic, None, &[])
        .expect("Failed to connect netlink socket");

    println!("Socket connected");

    let id = socket
        .resolve_genl_family(NL80211_FAMILY_NAME)
        .expect("Failed to resolve nl80211 family");

    println!("Family resolved: {}", id);

    let genl_msghdr = {
        let attrs = GenlBuffer::<Nl80211Attr, Buffer>::new();
        Genlmsghdr::new(Nl80211Cmd::GetInterface, 1, attrs)
    };

    let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
    let payload = NlPayload::Payload(genl_msghdr);
    let nl_msghdr = Nlmsghdr::new(None, id, flags, None, None, payload);

    socket.send(nl_msghdr).expect("Failed to send message");

    let interfaces = socket
        .recv_all::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>()
        .iter()
        .flat_map(NlBuffer::iter)
        .filter_map(|nl_msghdr| nl_msghdr.get_payload().ok())
        .filter_map(|payload| Interface::try_from(payload.get_attr_handle().get_attrs()).ok())
        .collect::<HashSet<_>>();

    for interface in &interfaces {
        println!("{:?}", interface);
    }
}
