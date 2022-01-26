use anyhow::Result;
use nl80211scan;

#[tokio::main]
async fn main() -> Result<()> {
    let stations = nl80211scan::scan("wlan0").await?;

    for station in stations {
        println!("{} {}%", station.ssid, station.quality);
    }

    Ok(())
}
