#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use rados::{Config, ErrorKind, LockMode, LockOptions, OperationOptions, SecretKey};
use serde::Serialize;

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct Report {
    class_execution: bool,
    lock_contention: bool,
    lock_renew: bool,
    lock_break: bool,
    lock_shared: bool,
    lock_expiry: bool,
    watch_ack: bool,
    notify_timeout: bool,
    native_locks: bool,
    native_watch: bool,
    native_notify: bool,
    watch_remap: bool,
    osd_restart: bool,
    explicit_unregister: bool,
    watch_shutdown: bool,
    client_shutdown: bool,
}

#[derive(serde::Deserialize)]
struct NativeSeed {
    native_exec_result: usize,
    native_exec_output: String,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("rados-r10-live: {error}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments()?;
    let first = connect(&arguments).await?;
    let second = connect(&arguments).await?;
    let pool = first.open_pool("p10-data", options()).await?;
    let other_pool = second.open_pool("p10-data", options()).await?;
    let object = pool.object("coordination")?;
    let other = other_pool.object("coordination")?;
    object.write_full(b"ready", options()).await?;
    let directory = Path::new(required(&arguments, "coordination-dir")?);

    let native_seed: NativeSeed =
        serde_json::from_slice(&fs::read(directory.join("native-seed.json"))?)?;
    let native_output = decode_hex(&native_seed.native_exec_output)?;
    let class_result = pool
        .object("class-exec")?
        .exec(b"lock", b"list_locks", [], options())
        .await?;
    require(
        class_result.code == 0
            && class_result.data == native_output
            && native_seed.native_exec_result == class_result.data.len(),
        "generic class execution mismatch",
    )?;

    wait_for(directory.join("native-watch-ready")).await?;
    let native_cookie = fs::read_to_string(directory.join("native-watch-ready"))?
        .trim()
        .parse::<u64>()?;
    let native_lockers = object.list_lockers("native-lock", options()).await?;
    require(
        native_lockers.len() == 1
            && native_lockers[0].cookie == "native-cookie"
            && native_lockers[0].description == "native holder renewed",
        "native lock metadata",
    )?;
    break_confirmed(
        &other,
        "native-lock",
        &native_lockers[0].client,
        &native_lockers[0].cookie,
    )
    .await?;
    lock_confirmed(
        &object,
        "native-release",
        LockMode::Exclusive,
        LockOptions {
            cookie: "rust-after-native-release".into(),
            ..LockOptions::default()
        },
    )
    .await?;
    unlock_confirmed(&object, "native-release", "rust-after-native-release").await?;
    lock_confirmed(
        &object,
        "native-shared",
        LockMode::Shared,
        LockOptions {
            cookie: "rust-native-shared".into(),
            tag: "native-shared-tag".into(),
            description: "Rust shared holder".into(),
            ..LockOptions::default()
        },
    )
    .await?;
    require(
        object.list_lockers("native-shared", options()).await?.len() == 2,
        "mixed shared lock",
    )?;
    unlock_confirmed(&object, "native-shared", "rust-native-shared").await?;
    wait_for_lock(&object, "native-expiry", "rust-after-native-expiry").await?;
    object
        .unlock("native-expiry", "rust-after-native-expiry", options())
        .await?;

    let mut exclusive = LockOptions {
        cookie: "first".into(),
        description: "Rust holder".into(),
        duration: Duration::from_secs(30),
        ..LockOptions::default()
    };
    lock_confirmed(&object, "exclusive", LockMode::Exclusive, exclusive.clone()).await?;
    require_contended(
        &other,
        "exclusive",
        LockMode::Exclusive,
        LockOptions {
            cookie: "second".into(),
            ..LockOptions::default()
        },
    )
    .await?;
    exclusive.renew = true;
    lock_confirmed(&object, "exclusive", LockMode::Exclusive, exclusive).await?;
    let holder = object.list_lockers("exclusive", options()).await?.remove(0);
    break_confirmed(&other, "exclusive", &holder.client, &holder.cookie).await?;
    require(
        object
            .unlock("exclusive", "first", options())
            .await
            .is_err(),
        "unlock after break",
    )?;

    lock_confirmed(
        &object,
        "rust-lock",
        LockMode::Exclusive,
        LockOptions {
            cookie: "rust-cookie".into(),
            duration: Duration::from_secs(30),
            ..LockOptions::default()
        },
    )
    .await?;
    fs::write(directory.join("native-verify-ready"), [])?;
    wait_for(directory.join("native-verify-complete")).await?;
    require(
        object
            .unlock("rust-lock", "rust-cookie", options())
            .await
            .is_err(),
        "native break Rust lock",
    )?;

    object
        .lock(
            "shared",
            LockMode::Shared,
            LockOptions {
                cookie: "shared-first".into(),
                tag: "shared-tag".into(),
                duration: Duration::from_secs(30),
                ..LockOptions::default()
            },
            options(),
        )
        .await?;
    other
        .lock(
            "shared",
            LockMode::Shared,
            LockOptions {
                cookie: "shared-second".into(),
                tag: "shared-tag".into(),
                duration: Duration::from_secs(30),
                ..LockOptions::default()
            },
            options(),
        )
        .await?;
    require(
        object.list_lockers("shared", options()).await?.len() == 2,
        "shared lock holders",
    )?;
    object.unlock("shared", "shared-first", options()).await?;
    other.unlock("shared", "shared-second", options()).await?;
    object
        .lock(
            "expiring",
            LockMode::Exclusive,
            LockOptions {
                cookie: "expiring".into(),
                duration: Duration::from_secs(1),
                ..LockOptions::default()
            },
            options(),
        )
        .await?;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    other
        .lock(
            "expiring",
            LockMode::Exclusive,
            LockOptions {
                cookie: "after-expiry".into(),
                ..LockOptions::default()
            },
            options(),
        )
        .await?;
    other.unlock("expiring", "after-expiry", options()).await?;

    let native_watchers = object.list_watchers(options()).await?;
    require(
        native_watchers
            .iter()
            .any(|watcher| watcher.cookie == native_cookie),
        "native watcher listing",
    )?;
    let (native_reply, native_outcome) = object.notify(b"go-native", options()).await;
    native_outcome?;
    require(
        native_reply.acknowledged.len() == 1,
        "Rust notify native watch",
    )?;

    let (native_target, mut native_events) = object.watch(4, options()).await?;
    fs::write(directory.join("go-watch-ready"), [])?;
    let event = next_event(&mut native_events).await?;
    require(event.data == b"native-go", "native notify Rust watch")?;
    native_target
        .ack(event.notify_id, b"go-ack", options())
        .await?;
    native_target.close(options()).await?;

    let (remap_watch, mut remap_events) = object.watch(8, options()).await?;
    require(
        object.list_watchers(options()).await?.len() == 2,
        "pre-remap watcher count",
    )?;
    fs::write(directory.join("remap-watch-ready"), [])?;
    wait_for(directory.join("remap-complete")).await?;
    wait_for_watchers(
        &object,
        &[native_cookie, remap_watch.cookie()],
        Duration::from_secs(5),
    )
    .await?;
    notify_and_ack(
        &other,
        &remap_watch,
        &mut remap_events,
        b"after-remap-native",
    )
    .await?;
    fs::write(directory.join("remap-verified"), [])?;
    wait_for(directory.join("restart-complete")).await?;
    wait_for_watchers(
        &object,
        &[native_cookie, remap_watch.cookie()],
        Duration::from_secs(5),
    )
    .await?;
    notify_and_ack(
        &other,
        &remap_watch,
        &mut remap_events,
        b"after-restart-native",
    )
    .await?;
    remap_watch.close(options()).await?;
    wait_for_watchers(&object, &[], Duration::ZERO).await?;

    let (watch, mut events) = object.watch(8, options()).await?;
    let notifier = other.clone();
    let notify = tokio::spawn(async move { notifier.notify(b"notify", options()).await });
    let event = next_event(&mut events).await?;
    require(event.data == b"notify", "watch payload")?;
    watch.ack(event.notify_id, b"ack", options()).await?;
    let (reply, outcome) = notify.await?;
    outcome?;
    require(
        reply.acknowledged.len() == 1 && reply.timed_out.is_empty(),
        "notify acknowledgment",
    )?;

    let notifier = other.clone();
    let timeout_notify = tokio::spawn(async move {
        notifier
            .notify(b"timeout", OperationOptions::default())
            .await
    });
    require(
        next_event(&mut events).await?.data == b"timeout",
        "timeout payload",
    )?;
    let (timeout_reply, timeout_outcome) = timeout_notify.await?;
    require(
        timeout_outcome.is_err() && timeout_reply.timed_out.len() == 1,
        "partial timeout result",
    )?;
    watch.close(options()).await?;
    wait_for_watchers(&object, &[], Duration::ZERO).await?;

    let (shutdown_watch, mut shutdown_events) = object.watch(1, options()).await?;
    let mut shutdown_done = shutdown_watch.done();
    let notifier = other.clone();
    let pending = tokio::spawn(async move { notifier.notify(b"shutdown", options()).await });
    require(
        next_event(&mut shutdown_events).await?.data == b"shutdown",
        "shutdown payload",
    )?;
    let shutdown_started = Instant::now();
    let shutdown_error = first
        .shutdown(options())
        .await
        .expect_err("shutdown with an unacknowledged notification must be uncertain");
    require(
        shutdown_error.kind() == ErrorKind::OutcomeUnknown,
        "shutdown outcome classification",
    )?;
    require(
        shutdown_started.elapsed() <= Duration::from_secs(1),
        "client shutdown bound",
    )?;
    if !*shutdown_done.borrow() {
        tokio::time::timeout(Duration::from_secs(1), shutdown_done.wait_for(|done| *done))
            .await??;
    }
    require(
        tokio::time::timeout(Duration::from_secs(1), shutdown_events.recv())
            .await?
            .is_none(),
        "callback delivered after client shutdown",
    )?;
    second.close();
    let (_, pending_outcome) = pending.await?;
    let pending_error = pending_outcome.expect_err("pending notify settled successfully");
    require(
        pending_error.is_kind(ErrorKind::Closed)
            && pending_error.is_kind(ErrorKind::OutcomeUnknown),
        "pending notify shutdown classification",
    )?;

    serde_json::to_writer(
        std::io::stdout(),
        &Report {
            class_execution: true,
            lock_contention: true,
            lock_renew: true,
            lock_break: true,
            lock_shared: true,
            lock_expiry: true,
            watch_ack: true,
            notify_timeout: true,
            native_locks: true,
            native_watch: true,
            native_notify: true,
            watch_remap: true,
            osd_restart: true,
            explicit_unregister: true,
            watch_shutdown: true,
            client_shutdown: true,
        },
    )?;
    println!();
    Ok(())
}

async fn lock_confirmed(
    object: &rados::ObjectRef,
    name: &str,
    mode: LockMode,
    lock_options: LockOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let cookie = lock_options.cookie.clone();
    match object.lock(name, mode, lock_options, options()).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::OutcomeUnknown => {
            let lockers = object.list_lockers(name, options()).await?;
            require(
                lockers
                    .iter()
                    .any(|locker| locker.cookie == cookie && locker.mode == mode),
                "unknown lock outcome was not confirmed",
            )
        }
        Err(error) => Err(error.into()),
    }
}

async fn require_contended(
    object: &rados::ObjectRef,
    name: &str,
    mode: LockMode,
    lock_options: LockOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let cookie = lock_options.cookie.clone();
    match object.lock(name, mode, lock_options, options()).await {
        Ok(()) => Err("lock unexpectedly bypassed contention".into()),
        Err(error) if error.kind() == ErrorKind::OutcomeUnknown => {
            let lockers = object.list_lockers(name, options()).await?;
            require(
                lockers.iter().all(|locker| locker.cookie != cookie),
                "ambiguous contention acquired the lock",
            )
        }
        Err(_) => Ok(()),
    }
}

async fn unlock_confirmed(
    object: &rados::ObjectRef,
    name: &str,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match object.unlock(name, cookie, options()).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::OutcomeUnknown => {
            let lockers = object.list_lockers(name, options()).await?;
            require(
                lockers.iter().all(|locker| locker.cookie != cookie),
                "unknown unlock outcome was not confirmed",
            )
        }
        Err(error) => Err(error.into()),
    }
}

async fn break_confirmed(
    object: &rados::ObjectRef,
    name: &str,
    client: &str,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match object.break_lock(name, client, cookie, options()).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::OutcomeUnknown => {
            let lockers = object.list_lockers(name, options()).await?;
            require(
                lockers
                    .iter()
                    .all(|locker| locker.client != client || locker.cookie != cookie),
                "unknown break outcome was not confirmed",
            )
        }
        Err(error) => Err(error.into()),
    }
}

async fn notify_and_ack(
    notifier: &rados::ObjectRef,
    watch: &rados::Watch,
    events: &mut tokio::sync::mpsc::Receiver<rados::WatchEvent>,
    payload: &'static [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let notifier = notifier.clone();
    let pending = tokio::spawn(async move { notifier.notify(payload, options()).await });
    let event = next_event(events).await?;
    require(event.data == payload, "notification payload")?;
    watch.ack(event.notify_id, [], options()).await?;
    let (reply, outcome) = pending.await?;
    outcome?;
    require(
        reply.acknowledged.len() == 2,
        "mixed watcher acknowledgments",
    )?;
    Ok(())
}

async fn next_event(
    events: &mut tokio::sync::mpsc::Receiver<rados::WatchEvent>,
) -> Result<rados::WatchEvent, Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(15), events.recv())
        .await?
        .ok_or_else(|| "watch event channel closed".into())
}

async fn wait_for_watchers(
    object: &rados::ObjectRef,
    cookies: &[u64],
    stable_for: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut stable_since = None;
    loop {
        match object.list_watchers(options()).await {
            Ok(watchers)
                if watchers.len() == cookies.len()
                    && cookies
                        .iter()
                        .all(|cookie| watchers.iter().any(|watcher| watcher.cookie == *cookie)) =>
            {
                let since = stable_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= stable_for {
                    return Ok(());
                }
            }
            _ => stable_since = None,
        }
        require(Instant::now() < deadline, "watcher stabilization timeout")?;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_lock(
    object: &rados::ObjectRef,
    name: &str,
    cookie: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match object
            .lock(
                name,
                LockMode::Exclusive,
                LockOptions {
                    cookie: cookie.into(),
                    ..LockOptions::default()
                },
                options(),
            )
            .await
        {
            Ok(()) => return Ok(()),
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn connect(
    arguments: &HashMap<String, String>,
) -> Result<rados::Client, Box<dyn std::error::Error>> {
    let key = fs::read(required(arguments, "key")?)?;
    let config = Config::default()
        .with_monitors(required(arguments, "monitors")?.split(','))?
        .with_entity("client.p09")?
        .with_cluster_fsid(required(arguments, "fsid")?)?
        .with_key(SecretKey::new(key.trim_ascii())?)
        .with_timeouts(
            Duration::from_secs(10),
            Duration::from_secs(15),
            Duration::from_secs(4),
        )?;
    let client = rados::Client::new(config)?;
    client.connect(options()).await?;
    Ok(client)
}

fn options() -> OperationOptions {
    OperationOptions::new().with_deadline(Instant::now() + Duration::from_secs(120))
}

async fn wait_for(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !path.as_ref().exists() {
        require(Instant::now() < deadline, "control wait timeout")?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    require(value.len().is_multiple_of(2), "odd hex length")?;
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            let pair = &value.as_bytes()[offset..offset + 2];
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn require(condition: bool, message: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn arguments() -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut result = HashMap::new();
    let mut values = std::env::args().skip(1);
    while let Some(name) = values.next() {
        let value = values.next().ok_or("missing argument value")?;
        result.insert(
            name.strip_prefix("--").ok_or("invalid argument")?.into(),
            value,
        );
    }
    Ok(result)
}

fn required<'a>(
    arguments: &'a HashMap<String, String>,
    name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    arguments
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing --{name}").into())
}
