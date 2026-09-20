use rados::{Client, Config, OperationOptions};

async fn inspect_cluster(client: &Client) -> rados::Result<()> {
    let options = OperationOptions::new();
    let stats = client.cluster_stats(options.clone()).await?;
    println!(
        "cluster: {} KiB available, {} objects",
        stats.kib_available, stats.objects
    );

    for pool_name in client.list_pools(options.clone()).await? {
        let pool = client.open_pool(&pool_name, options.clone()).await?;
        let pool_stats = pool.stats(options.clone()).await?;
        println!(
            "{pool_name}: {} bytes, {} objects",
            pool_stats.bytes_used, pool_stats.objects
        );
        for application in pool.list_applications(options.clone())? {
            let metadata = pool.list_application_metadata(&application, options.clone())?;
            println!("  {application}: {metadata:?}");
        }
    }

    let (health, outcome) = client
        .monitor_command(br#"{"prefix":"health","format":"json"}"#, [], options)
        .await;
    outcome?;
    println!("health status: {}", health.status);
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> rados::Result<()> {
    let config = Config::load("/etc/ceph/ceph.conf")?;
    let client = Client::new(config)?;
    client.connect(OperationOptions::new()).await?;
    inspect_cluster(&client).await
}
