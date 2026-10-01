# Security boundary

## 現在保証すること

- DPAPIはCurrentUser scopeだけを使用し、LocalMachine scopeへfallbackしません。
- `CRYPTPROTECT_UI_FORBIDDEN`により、対話UIやLinux GUIを要求しません。
- ciphertextはWindows LocalAppDataの継承ACL下へ保存します。
- helper pathとSHA-256をWSL側で起動直前に再照合します。
- helper processは環境を全消去し、`WSL_INTEROP`も継承しません。
- secretは匿名stdin/stdout pipeのbounded opaque frame以外へ出しません。
- control JSONは未知field、未知schema、未知protocol、未知operationを拒否します。
- record更新は排他的lock、atomic write-through replacement、read-backで確認します。
- namespaceとcredential IDはDPAPI entropyと暗号化recordの両方へ束縛します。
- revisionは秘密値と無関係なランダムopaque CAS tokenだけをmetadataへ返します。
- record読取りはopen後にもfile種別、reparse属性、サイズ上限を検証します。
- replacementはsource、destination、親directoryを前後で検証します。
- secretを含むallocationは所有範囲でzeroizeします。
- error responseは固定されたreason codeとmetadataだけを返します。
- operation-onlyはPA署名、要求digest、action、nonce、workload、audienceを完全一致で検証します。
- operation-onlyは別鍵で署名された短命なiHAT current-device statusをprovider内で検証します。
- operation-onlyはpairwise subject、端末proof key、posture revisionと4階層epochを検証します。
- operation-only v1や単一`revocation_epoch`の互換fallbackはありません。
- operation-onlyは要求全体/nonce/request IDをPreparedで固定し、秘密を含まないcanonical応答bytesを
  Completedとしてstdoutより先に永続化します。完全一致Completed retryだけが同じbytesを返します。
- operation ledgerはopenしたowner directoryのidentityを固定し、fd/handle相対I/O、0600 file、
  nlink 1、排他lock、fsync、atomic replace、directory fsyncを要求します。

この実装はWindows LocalAppDataへ独自DACLを設定しません。Windowsユーザーprofileから継承した
ACLとDPAPI CurrentUserを使用します。したがって「専用service identityだけが読める」とは
表現しません。配備時はWindows profile、release binary、WSL distributionを同じ
owner-local trust domainとして扱います。

同一Windowsユーザーは継承DACL上で保存directoryを変更できるため、pathベースWindows APIの
directory差替えに対する完全な敵対的same-user隔離は保証しません。open中fileは共有を拒否し、
全directory/fileでreparseを拒否し、replacement前後と復号read-backを検証しますが、
same-userを非信頼とする配備では専用Windows service identityと明示DACLが必要です。

## Owner-local TCBの限界

Windows Credential ManagerやDPAPI CurrentUserは、同じWindowsアカウントで動作する悪意ある
processからの隔離境界ではありません。明示的なexport操作である`get`は秘密値を専用WSL processへ返すため、
WindowsアカウントまたはそのWSL workloadが侵害された場合は資格情報をrotationします。

helper digest pinは改変検知であり、Windows code-signing chainの代替ではありません。
releaseではAuthenticode、artifact provenance、SBOM、Windows Defender/Application Control等を
別途適用します。ext4上のPEも実行できますが、固定pathとdigestの両方が必要です。

## Operation-only境界

PA鍵、GitHub App RSA鍵、証明書鍵は、秘密値を返す`get`ではなく、Windows CNG named keyへ接続した
閉じたoperationだけで利用します。registry済みoperation-only credential IDへのgeneric
`put/get/delete`は拒否し、generic custodyをfallbackにはしません。鍵生成はhelperの外で行い、
配備時にCNG export policyをnon-exportableにし、helperも署名前に`NCRYPT_EXPORT_POLICY_PROPERTY`を
確認してexport/archive許可が一つでもある鍵を拒否します。

provider自身はiHATへオンライン問い合わせをしませんが、request内の短命な
`CurrentDeviceStatusV1`を独立した固定status鍵で検証します。PA認可のidentity値、statusの現在値、
有効期間を完全一致で比較するため、端末Aのdevice epoch更新はAだけを拒否し、同じpairwise subjectでも
別のproof keyとepochを持つ端末Bを失効させません。subjectまたはservice epochを上げる操作は、
意図どおり同じscopeの全端末へ影響します。statusまたはPA認可のどちらか一方だけでは操作できません。

LocalAppDataのtrust/registryファイルはreparse point、未知field、重複ID、上限超過を拒否しますが、
同一Windowsユーザーによる正規fileの置換をOS強制で防ぐ独自DACLはまだ設定しません。専用service
identityを使わない配備では、Windows profileとrelease ceremonyをowner-local TCBとして扱います。

Operation ledgerはCompletedを7日後、Preparedを認可expiryから7日後に自動Cancelledへ移し、
Cancelled tombstoneを30日保持します。公開Cancel routeはなく、回復窓内だけ完全一致Preparedを
同じcredential revisionへ再実行できます。各Preparedは最大応答容量を副作用前に予約し、record/cache
quotaを超える要求はbackend呼出し前に拒否します。durable clock high-watermarkより過去へのrollbackも
拒否します。anchorより一世代先の完全なstateだけをcrash forward-recoveryし、その他のrollback、
未知file、旧`CWN1` record、symlink、hardlink、FIFO、oversizeを自動移行しません。

Completed cacheはrequest ID、credential ID/revision、action/result、secret flagsを再検証します。
秘密鍵、PA秘密、credential plaintextは保存しません。保持期間を超えた応答の再取得はできないため、
呼出側は7日以内にexact retryし、それ以後は新しいnonce/request IDで再認可します。

## Incident response

helper digest、reparse point、ciphertext、revision、read-backの不一致は自動修復せず停止します。
該当credentialをprovider側で失効し、保存blobとmetadata-only監査証跡を保全し、PA revocation
epochを進め、新しいWindows user sessionでrotationします。秘密blobをログやissueへ添付しません。

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
