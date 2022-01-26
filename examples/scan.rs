use anyhow::Result;
use nl80211scan;

#[tokio::main]
async fn main() -> Result<()> {
    nl80211scan::scan().await
}
