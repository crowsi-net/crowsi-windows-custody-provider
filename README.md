# Crowsi Windows Custody Provider

Windows上のDPAPI CurrentUserを、GUIのないWSLから利用するための独立したRust境界です。
Linux Secret Service、GNOME Keyring、D-Bus、Wayland、PowerShellに依存しません。

## 配布物

- binary ID: `crowsi-windows-custody-provider`
- Windows build output: `crowsi-windows-custody-provider.exe`
- target: `x86_64-pc-windows-gnu`
- runtime schema: `crowsi://platform-custody/runtime/v1`
- provider kind: `windows-dpapi-user`
- protocol: `crowsi-windows-custody-v1`

Windows helperは引数を受け取りません。起動ごとにstdinからgeneric v1またはoperation-only v3の
1要求だけを処理し、stdoutへ
1応答を返して終了します。秘密値は`put`要求または`get`応答の独立したopaque frameにだけ
存在し、JSON、argv、環境変数、stderr、ログ、statusへ入りません。

WSL clientはhelperをPATHから探索しません。ext4またはDrvFS上の絶対・canonical・
non-symlink pathと`sha256:<64 lowercase hex>`を毎回照合し、環境を空にして起動します。
応答読取りは同時に行い、最大30秒でkillして必ずreapします。
現行WSLの`/init` binfmt経路は空の環境でもext4上のPEを起動できることを確認済みであり、
`WSL_INTEROP`を含むhost環境変数をhelperへ転送しません。

## API

```rust
use std::{path::PathBuf, time::Duration};
use crowsi_windows_custody_provider::{CustodyClient, HelperIdentity};

let helper = HelperIdentity::new(
    PathBuf::from("/opt/crowsi/native/crowsi-windows-custody-provider.exe"),
    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
)?;
let client = CustodyClient::new(
    helper, "coela.crowsi.credentials", Duration::from_secs(5)
)?;
let response = client.doctor("doctor-0001")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

本番設定は`RuntimeConfig`でnamespace、path、digest、protocol versionを固定します。
timeoutはconsumer側constructorで指定します。公開操作は
`doctor`、`put`、`metadata`、`get`、`delete`です。更新と削除には現在revisionを指定し、
競合や古い読取りを拒否します。revisionは`rev1:<64 lowercase hex>`形式のランダムな
opaque CAS tokenであり、秘密値のdigestやfingerprintではありません。

## Wire contract

各frameは4-byte big-endian lengthと可変長bodyです。control JSONは16 KiB、opaque secretは
64 KiBを上限とし、空、途中終了、余剰frame、未知fieldを拒否します。controlとsecretを
同じJSONや固定長recordに結合しません。

helperはLocalAppData配下へDPAPI ciphertextだけを保存します。DPAPIには
`CRYPTPROTECT_UI_FORBIDDEN`を指定するため、Linux GUIもWindows promptも要求しません。
保存更新は同一directoryの新規一時file、flush、write-through replacement、復号read-backで
確定します。DPAPI optional entropyと暗号化recordの両方へnamespaceとcredential IDを
長さ区切りで束縛するため、同じIDのblobを別namespaceへコピーしても復号できません。
reparse point、読み取り上限超過、長さ不整合、cipher digest不整合、DPAPI改ざん、復号recordの
namespace/ID/revision/secret digest不整合を拒否します。

`get`は既存consumerの移行用に秘密値を返す明示的なexport境界です。公開APIは
`ClientResponse::expose_secret` callback内だけで値を参照でき、secret wrapperは
`Debug`、`Clone`、serializeを実装しません。署名鍵はoperation-only providerへ移行し、
このgeneric exportをfallbackとして使いません。

WSL側のoperation-only呼出しは`CustodyClient::execute_operation`を使用します。generic APIと同じ
helper path/digest再検証、空環境、匿名pipe、timeout/kill/reap境界を通りますが、opaque secret frameは
送受信しません。

## Operation-only v3

署名鍵とprovider固有credentialは、秘密値を返さず閉じた操作だけを実行します。現行契約は
`operation-request/v3`、`operation-authorization/v3`、`operation-response/v3`だけです。
旧v1 schema、旧`account_id`、単一`revocation_epoch`を受理する互換fallbackはありません。

PA認可は、`service_id`、serviceごとの`pairwise_subject`、`device_id`、端末固有の
`device_proof_key_ref`、端末postureとrevision、subject/service/device/sessionの4つの
revocation epoch、workload、audience、action、要求digest、one-use nonceへ署名されます。
provider自身が、独立status鍵で署名されたiHAT `CurrentDeviceStatusV1`とPA認可を固定した別鍵で
検証します。呼出側が作成した`OperationContext`をproduction commandへ渡す経路はありません。
全項目の完全一致、`service:crowsi`、compliant posture、固定workload/audience、status内に収まる
最大60秒の認可有効期間を確認してから、認可とstatusを含む要求全体、nonce、request ID、
credential revisionを一つのdurable Prepared recordへ束縛し、Windows側の閉じた操作を呼びます。
結果は秘密値を含まないcanonical response bytesとして同じ排他ledgerへCompleted commitしてから
stdoutへ返します。Completedの完全一致retryは現在のPA/status/config検証より先に同じbytesを返すため、
stdout喪失、再起動、認可失効、検証鍵rotation後もbackendを再実行しません。Preparedの完全一致retryは
保存済みcredential ID/class/revisionを再確認した後だけ決定的backendを再実行します。

Completedは7日保持後にCancelled tombstoneとなり、Preparedも認可expiryから7日の回復窓後に
自動Cancelledとなります。Cancelledは完全一致でも拒否し、30日後に削除します。公開wireに手動Cancel
routeはありません。応答容量はPreparedごとに副作用前予約され、ledgerはrecord/cache quotaとdurable
clock high-watermarkを持ちます。時計rollback、quota超過、旧`CWN1` nonce fileはfail-closeです。
ledgerは秘密鍵、PA秘密、credential plaintextをcacheしません。

device epochは端末ごとに比較します。端末Aだけを失効した場合、Aの古い認可は拒否されますが、
別のproof keyとdevice epochを持つ端末Bの認可には影響しません。応答は署名等の導出結果、
credential ID、revisionだけであり、秘密鍵やcredential plaintextを含みません。

Windows production backendはLocalAppData下のclosedな`operation-trust-v1.json`と
`cng-key-registry-v1.json`を読み、registryに登録されたWindows CNG named keyだけを
`NCryptOpenKey`/`NCryptSignHash`で操作します。registryは鍵名と公開metadataだけを持ち、秘密鍵blobを
保持しません。CNG keyは配備時にnon-exportable policyで作成し、helperには生成・export APIを
公開しません。generic `put/get/delete`はregistry済みcredential IDを拒否します。

配備schemaは`schemas/operation-request-v3.schema.json`、`operation-response-v3.schema.json`、
`operation-trust-v1.schema.json`、`cng-key-registry-v1.schema.json`です。

## Verification

LinuxではWindows binaryをbuildせず、共有protocolとWSL clientを検証します。

```bash
cargo test --locked --offline
cargo clippy --locked --offline --lib -- -D warnings
node "$WONDERLAND_ROOT/tools/check-source-layout.mjs" .
```

Windows buildと実DPAPI試験は署名済みrelease pipelineで別途実行します。

WSLから実DPAPI lifecycleを確認する場合だけ、digest pin対象のWindows PEを明示して
ignored testを実行します。testはランダムnamespace、credential ID、secretで
doctor→put→metadata→get→delete→not-foundを検証し、失敗時も削除を試みます。

```bash
CROWSI_WINDOWS_CUSTODY_PROVIDER_EXECUTABLE=/absolute/release/provider.exe \
  cargo test --locked --offline --test windows-dpapi-live -- --ignored --exact \
  live_dpapi_lifecycle_is_isolated_and_recoverable
```
