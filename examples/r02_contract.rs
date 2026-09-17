use rados::{
    CancellationToken, ClassResult, Client, Config, ErrorKind, Namespace, NotifyAcknowledgment,
    NotifyReply, NotifyTimeout, ObjectPage, OpResult, OperationOptions, ReadOp, SecretKey,
    SubOperationFlags, Watch, WriteOp,
};
use std::time::Duration;

fn frozen_owned_results(
    operation: OpResult,
    class: ClassResult,
    page: ObjectPage,
    notify: NotifyReply,
) -> (OpResult, ClassResult, ObjectPage, NotifyReply) {
    (operation, class, page, notify)
}

fn frozen_watch_handle(watch: &Watch) -> u64 {
    watch.cookie()
}

fn main() -> rados::Result<()> {
    let key = SecretKey::new(b"AQIDBA==")?;
    let config = Config::default()
        .with_monitors(["127.0.0.1:3300"])?
        .with_entity("client.example")?
        .with_key(key)
        .with_timeouts(Duration::ZERO, Duration::ZERO, Duration::ZERO)?;
    let client = Client::new(config)?;
    let pool = client.pool(b"data")?.with_namespace([0xff, 0])?;
    let object = pool.object(b"object\0name")?;
    assert_eq!(
        object.pool().namespace(),
        Namespace::new([0xff, 0])?.as_bytes()
    );

    let source = b"owned payload".to_vec();
    let _write = WriteOp::new().create(true)?.write(0, &source)?;
    let _read = ReadOp::new().assert_exists()?.read(0, 4)?.stat()?;

    let cancellation = CancellationToken::new();
    let _options = OperationOptions::new().with_cancellation(cancellation);
    let unknown = rados::Error::outcome_unknown(ErrorKind::Canceled);
    assert!(unknown.is_kind(ErrorKind::OutcomeUnknown));
    assert!(unknown.is_kind(ErrorKind::Canceled));

    let _ = frozen_owned_results;
    let _ = frozen_watch_handle;
    let _ = SubOperationFlags::FAIL_OK;
    let _ = NotifyAcknowledgment {
        client: 1,
        cookie: 2,
        data: Vec::new(),
    };
    let _ = NotifyTimeout {
        client: 1,
        cookie: 2,
    };
    Ok(())
}
