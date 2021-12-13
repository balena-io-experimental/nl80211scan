mod enums;

#[allow(dead_code, non_upper_case_globals, non_camel_case_types)]
mod consts;

use std::convert::{TryFrom, TryInto};
use std::hash::Hash;

use anyhow::Result;

use macaddr::MacAddr6;

use neli::consts::nl::{NlmF, NlmFFlags, Nlmsg};
use neli::consts::socket::NlFamily;
use neli::consts::MAX_NL_LENGTH;
use neli::genl::{Genlmsghdr, Nlattr};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::tokio::NlSocket;
use neli::socket::NlSocketHandle;
use neli::types::{Buffer, GenlBuffer};

use enums::{Nl80211Attr, Nl80211Cmd};

const NL80211_FAMILY_NAME: &str = "nl80211";
const SCAN_MULTICAST_NAME: &str = "scan";

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
            _ => InterfaceType::Unspecified,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Interface {
    name: String,
    index: u32,
    iftype: InterfaceType,
    wiphy: u32,
    wdev: u64,
    mac_address: MacAddr6,
}

impl TryFrom<&Genlmsghdr<Nl80211Cmd, Nl80211Attr>> for Interface {
    type Error = anyhow::Error;

    fn try_from(payload: &Genlmsghdr<Nl80211Cmd, Nl80211Attr>) -> Result<Self, Self::Error> {
        let attrs = payload.get_attr_handle();
        let name = attrs.get_attr_payload_as_with_len(Nl80211Attr::Ifname)?;
        let index = attrs.get_attr_payload_as(Nl80211Attr::Ifindex)?;
        let iftype = attrs
            .get_attr_payload_as::<u32>(Nl80211Attr::Iftype)?
            .into();
        let wiphy = attrs.get_attr_payload_as(Nl80211Attr::Wiphy)?;
        let wdev = attrs.get_attr_payload_as(Nl80211Attr::Wdev)?;
        let mac_bytes: [u8; 6] = attrs
            .get_attr_payload_as_with_len::<&[u8]>(Nl80211Attr::Mac)?
            .try_into()?;
        let mac_address = mac_bytes.into();
        Ok(Interface {
            name,
            index,
            iftype,
            wiphy,
            wdev,
            mac_address,
        })
    }
}

pub async fn scan() {
    let mut socket = NlSocketHandle::connect(NlFamily::Generic, None, &[])
        .expect("Failed to connect netlink socket");

    println!("Socket connected");

    let id = socket
        .resolve_genl_family(NL80211_FAMILY_NAME)
        .expect("Failed to resolve nl80211 family");

    println!("Family resolved: {}", id);

    let mut socket = NlSocket::new(socket).unwrap();

    let genl_msghdr = {
        let attrs = GenlBuffer::<Nl80211Attr, Buffer>::new();
        Genlmsghdr::new(Nl80211Cmd::GetInterface, 1, attrs)
    };

    let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
    let payload = NlPayload::Payload(genl_msghdr);
    let nl_msghdr = Nlmsghdr::new(None, id, flags, None, None, payload);

    socket
        .send(&nl_msghdr)
        .await
        .expect("Failed to send message");

    let mut buf = vec![0; MAX_NL_LENGTH];

    let msgs = socket
        .recv::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(&mut buf)
        .await
        .unwrap();

    for msg in msgs {
        let payload = msg.get_payload().unwrap();
        if let Ok(interface) = Interface::try_from(payload) {
            println!("{:?}", interface);

            let genl_msghdr = {
                let attr = Nlattr::new(false, true, Nl80211Attr::Ifindex, interface.index);
                Genlmsghdr::new(Nl80211Cmd::TriggerScan, 1, attr.into_iter().collect())
            };

            let mut socket = NlSocketHandle::connect(NlFamily::Generic, None, &[]).unwrap();

            let nl_msghdr = {
                let id = socket.resolve_genl_family(NL80211_FAMILY_NAME).unwrap();
                let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Ack]);
                let payload = NlPayload::Payload(genl_msghdr);
                Nlmsghdr::new(None, id, flags, None, None, payload)
            };

            let mut socket = NlSocket::new(socket).unwrap();

            socket.send(&nl_msghdr).await.unwrap();

            let mut buf = vec![0; MAX_NL_LENGTH];

            socket.recv::<Nlmsg, Buffer>(&mut buf).await.unwrap();

            let mut socket = NlSocketHandle::connect(NlFamily::Generic, None, &[]).unwrap();

            let id = socket
                .resolve_nl_mcast_group(NL80211_FAMILY_NAME, SCAN_MULTICAST_NAME)
                .unwrap();
            socket.add_mcast_membership(&[id]).unwrap();

            let mut socket = NlSocket::new(socket).unwrap();

            let mut buf = vec![0; MAX_NL_LENGTH];

            let received_new_scan_notification = socket
                .recv::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(&mut buf)
                .await
                .unwrap()
                .iter()
                .filter_map(|nl_msghdr| nl_msghdr.get_payload().ok())
                .any(|payload| payload.cmd == Nl80211Cmd::NewScanResults);
            if received_new_scan_notification {
                println!("Return scan results");
            } else {
                println!("Already scanning");
            }
        }
    }
}
