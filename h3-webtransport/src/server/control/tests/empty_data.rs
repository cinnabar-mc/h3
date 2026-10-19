use bytes::Bytes;
use std::time::Duration;

use crate::{capsule::encode_close, SessionClose};

use super::Fixture;

#[tokio::test]
async fn session_close_empty_data_before_and_inside_capsule_is_not_eof() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut observed = Vec::new();
        let capsule = encode_close(42, "empty DATA");
        for split in [0, 3] {
            let mut fixture = Fixture::new().await;
            let result = {
                let session = fixture.session.as_ref().unwrap();
                let (sent, visible) = tokio::sync::oneshot::channel();
                let peer = async {
                    if split != 0 {
                        fixture
                            .request
                            .send_data(capsule.slice(..split))
                            .await
                            .unwrap();
                    }
                    fixture.request.send_data(Bytes::new()).await.unwrap();
                    fixture
                        .request
                        .send_data(capsule.slice(split..))
                        .await
                        .unwrap();
                    fixture.request.finish().await.unwrap();
                    sent.send(()).unwrap();
                };
                let host = async {
                    visible.await.unwrap();
                    let first = session.recv_session_close().await;
                    let repeated = session.recv_session_close().await;
                    (first, repeated)
                };
                let ((), result) = tokio::join!(peer, host);
                result
            };
            fixture.retire().await;
            observed.push((split, result));
        }
        let expected = Some(SessionClose {
            code: 42,
            reason: Bytes::from_static(b"empty DATA"),
        });
        for (split, (first, repeated)) in observed {
            assert!(
                matches!((&first, &repeated), (Ok(first), Ok(repeated))
                    if first == &expected && repeated == &expected),
                "empty DATA at capsule offset {split} became body end: {first:?}, {repeated:?}"
            );
        }
    })
    .await
    .expect("finite actual CONNECT empty DATA exchange stalled");
}
