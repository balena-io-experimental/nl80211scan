mod enums;
mod interface;

#[allow(dead_code, non_upper_case_globals, non_camel_case_types)]
mod consts;

use std::hash::Hash;
use std::io::Cursor;
use std::io::Read;

use anyhow::{bail, Context, Result};

use byteorder::ReadBytesExt;

use neli::attr::Attribute;
use neli::consts::nl::{NlmF, NlmFFlags, Nlmsg};
use neli::consts::socket::NlFamily;
use neli::consts::MAX_NL_LENGTH;
use neli::genl::{Genlmsghdr, Nlattr};
use neli::nl::{NlPayload, Nlmsghdr};
use neli::socket::tokio::NlSocket;
use neli::socket::NlSocketHandle;
use neli::types::{Buffer, GenlBuffer};

use crate::enums::{Nl80211Attr, Nl80211Bss, Nl80211Cmd};
use crate::interface::Interface;

const NL80211_FAMILY_NAME: &str = "nl80211";
const SCAN_MULTICAST_NAME: &str = "scan";
const WLAN_EID_SSID: u8 = 0;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Station {
    pub ssid: String,
    pub quality: u8,
}

pub async fn scan(interface: &str) -> Result<Vec<Station>> {
    let mut socket_handle = NlSocketHandle::connect(NlFamily::Generic, None, &[])
        .context("Failed to establish netlink socket")?;

    let nl_id = socket_handle
        .resolve_genl_family(NL80211_FAMILY_NAME)
        .context("Failed to resolve nl80211 family")?;

    let mut socket = NlSocket::new(socket_handle).context("Failed to connect main socket")?;

    let genl_msghdr = {
        let attrs = GenlBuffer::<Nl80211Attr, Buffer>::new();
        Genlmsghdr::new(Nl80211Cmd::GetInterface, 1, attrs)
    };

    let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
    let payload = NlPayload::Payload(genl_msghdr);
    let nl_msghdr = Nlmsghdr::new(None, nl_id, flags, None, None, payload);

    socket
        .send(&nl_msghdr)
        .await
        .expect("Failed to send get interface message");

    let interfaces = recv_all(&mut socket, |msg| {
        Interface::try_from(msg.get_payload().ok()?).ok()
    })
    .await
    .context("Failed to receive get interface response")?;

    let iface = interfaces
        .iter()
        .find(|iface| iface.name == interface)
        .context("Interface not found")?;

    let genl_msghdr = {
        let iface_attr = Nlattr::new(false, true, Nl80211Attr::Ifindex, iface.index)
            .context("Faled to create interface index attribute")?;
        let scan_attr = Nlattr::new(
            false,
            true,
            Nl80211Attr::ScanFlags,
            consts::NL80211_SCAN_FLAG_AP,
        )
        .context("Failed to create scan flags attribute")?;
        Genlmsghdr::new(
            Nl80211Cmd::TriggerScan,
            1,
            [iface_attr, scan_attr].into_iter().collect(),
        )
    };

    let nl_msghdr = {
        let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Ack]);
        let payload = NlPayload::Payload(genl_msghdr);
        Nlmsghdr::new(None, nl_id, flags, None, None, payload)
    };

    socket
        .send(&nl_msghdr)
        .await
        .context("Failed to send request scan message")?;

    let mut buf = vec![0; MAX_NL_LENGTH];
    socket
        .recv::<Nlmsg, Buffer>(&mut buf)
        .await
        .context("Failed to receive request scan acknowledgement")?;

    let mut socket_handle_mcast = NlSocketHandle::connect(NlFamily::Generic, None, &[])
        .context("Failed to connect multicast socket")?;

    let mcast_id = socket_handle_mcast
        .resolve_nl_mcast_group(NL80211_FAMILY_NAME, SCAN_MULTICAST_NAME)
        .context("Failed to resolve muticast group")?;
    socket_handle_mcast
        .add_mcast_membership(&[mcast_id])
        .context("Failed to add multicast membership")?;

    let mut socket_mcast =
        NlSocket::new(socket_handle_mcast).context("Failed to set up multicast socket")?;

    let mut buf = vec![0; MAX_NL_LENGTH];

    let msgs = socket_mcast
        .recv::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(&mut buf)
        .await
        .context("Failed to receive new scan results notification")?;

    let has_scan_results = msgs
        .iter()
        .filter_map(|nl_msghdr| nl_msghdr.get_payload().ok())
        .any(|payload| payload.cmd == Nl80211Cmd::NewScanResults);

    if !has_scan_results {
        bail!("No scan results received");
    }

    let genl_msghdr = {
        let attr = Nlattr::new(false, true, Nl80211Attr::Ifindex, iface.index);
        Genlmsghdr::new(Nl80211Cmd::GetScan, 1, attr.into_iter().collect())
    };

    let nl_msghdr = {
        let flags = NlmFFlags::new(&[NlmF::Request, NlmF::Dump]);
        let payload = NlPayload::Payload(genl_msghdr);
        Nlmsghdr::new(None, nl_id, flags, None, None, payload)
    };

    socket
        .send(&nl_msghdr)
        .await
        .context("Failed to send get scan results message")?;

    recv_all(&mut socket, |msg| {
        let payload = msg.get_payload().ok()?;
        let mut attrs = payload.get_attr_handle();
        let bss_attrs = attrs
            .get_nested_attributes::<Nl80211Bss>(Nl80211Attr::Bss)
            .ok()?;

        let signal_mbm = bss_attrs
            .get_attribute(Nl80211Bss::SignalMbm)?
            .get_payload_as::<i32>()
            .ok()?;

        let quality = dbm_level_to_quality(signal_mbm);

        let ie_attrs = bss_attrs.get_attribute(Nl80211Bss::InformationElements)?;

        let buffer = ie_attrs.payload();
        let mut cursor = Cursor::new(buffer.as_ref());
        let ssid_bytes = extract_ssid(&mut cursor);
        let ssid = String::from_utf8(ssid_bytes)
            .ok()
            .filter(|s| !s.is_empty())?;

        Some(Station { ssid, quality })
    })
    .await
    .context("Failed to receive get scan results response")
}

async fn recv_all<T, F>(socket: &mut NlSocket, mut f: F) -> Result<Vec<T>>
where
    F: FnMut(Nlmsghdr<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>) -> Option<T>,
{
    let mut items = Vec::new();

    'outer: loop {
        let mut buf = vec![0; MAX_NL_LENGTH];

        let msgs = socket
            .recv::<Nlmsg, Genlmsghdr<Nl80211Cmd, Nl80211Attr>>(&mut buf)
            .await
            .context("Failed to receive nl80211 command response")?;

        for msg in msgs {
            if msg.nl_type == Nlmsg::Done {
                break 'outer;
            }

            if let Some(item) = f(msg) {
                items.push(item);
            }
        }
    }

    Ok(items)
}

fn extract_ssid(cursor: &mut std::io::Cursor<&[u8]>) -> Vec<u8> {
    while let Some((eid, data)) = extract_element(cursor) {
        if eid == WLAN_EID_SSID {
            return data;
        }
    }

    Vec::new()
}

fn extract_element(cursor: &mut std::io::Cursor<&[u8]>) -> Option<(u8, Vec<u8>)> {
    let eid = cursor.read_u8().ok()?;
    let size = cursor.read_u8().ok()?;
    let mut data = vec![0u8; size as _];
    cursor.read_exact(&mut data).ok()?;
    Some((eid, data))
}

fn dbm_level_to_quality(signal: i32) -> u8 {
    let mut val = f64::from(signal) / 100.;
    val = val.clamp(-100., -40.);
    val = (val + 40.).abs();
    val = (100. - (100. * val) / 60.).round();
    val = val.clamp(0., 100.);
    val as u8
}
