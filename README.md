# cert-expiry-checker

SSL/TLS 証明書の有効期限と、ドメイン登録の有効期限をまとめてチェックする CLI ツールです。
Python 標準ライブラリのみで動作し、追加のパッケージインストールは不要です。

## 何をするツールか

指定した各ドメインについて、次の 2 つをチェックします。

1. **TLS 証明書**（`ssl` + `socket`、ポート 443）
   - 有効期限（`notAfter`）と残り日数
   - 発行者（Issuer）
   - サブジェクト CN / SAN（Subject Alternative Names）
   - 検証に失敗した証明書（期限切れ・自己署名など）も、検証なしで再接続して期限を読み取り、理由とともに報告します
2. **ドメイン登録の有効期限**（RDAP）
   - `https://rdap.org/domain/<domain>` に問い合わせ（リダイレクトは `urllib` が自動で追従）
   - レスポンスの `events` から `eventAction: "expiration"` を探して期限を取得
   - `www.example.com` のようなサブドメインで 404 の場合は、親ドメイン（`example.com`）で再試行
   - RDAP が使えない・期限イベントがない場合はクラッシュせず **UNKNOWN** として報告

1 つのドメインでエラーが起きても、他のドメインのチェックは続行されます（並列実行、出力順は入力順のまま）。

## 動作要件

- Python 3.11 以上
- 外部ライブラリ不要（標準ライブラリのみ）
- 対象ホストの 443 番ポートと `rdap.org`（および転送先の RDAP サーバ）へのネットワーク接続

## 使い方

### 引数でドメインを指定

```sh
python3 cert_checker.py example.com google.com
```

出力例:

```
DOMAIN       STATUS  CERT EXPIRES  DAYS  ISSUER                    DOMAIN EXPIRES  DAYS  NOTES
-----------  ------  ------------  ----  ------------------------  --------------  ----  -----
example.com  OK      2027-01-15      53  DigiCert Inc / DigiCert…  2027-08-13       262
google.com   OK      2027-01-26      64  Google Trust Services / …  2028-09-14       660

Checked 2 domain(s): 2 OK, 0 WARNING, 0 EXPIRED, 0 ERROR, 0 UNKNOWN
```

`host:port` 形式（例: `example.com:8443`）や URL（`https://example.com/path`）も受け付けます。

### ファイルから読み込む（`--file`）

```sh
python3 cert_checker.py --file domains.example.txt
```

ファイル形式は 1 行 1 ドメインです。`#` 以降はコメント、空行は無視されます（`domains.example.txt` を参照）。
`--file` は複数回指定でき、引数のドメインと組み合わせることもできます。重複は除外されます。

```text
# 本番ドメイン
example.com
google.com   # インラインコメントも可
```

### JSON で出力（`--json`）

```sh
python3 cert_checker.py --json example.com
```

JSON は標準出力に、サマリー行は標準エラー出力に出るため、`jq` などにそのままパイプできます。

```json
{
  "checked_at": "2026-11-23T12:00:00.000000Z",
  "warn_days": 30,
  "results": [
    {
      "domain": "example.com",
      "port": 443,
      "status": "OK",
      "cert": {
        "status": "OK",
        "not_after": "2027-01-15T23:59:59Z",
        "days_remaining": 53,
        "issuer": "DigiCert Inc / DigiCert Global G3 TLS ECC SHA384 2020 CA1",
        "subject_cn": "*.example.com",
        "sans": ["*.example.com", "example.com"],
        "verified": true,
        "error": null
      },
      "registration": {
        "status": "OK",
        "expiration": "2027-08-13T04:00:00Z",
        "days_remaining": 262,
        "rdap_url": "https://rdap.verisign.com/com/v1/domain/example.com",
        "error": null
      }
    }
  ],
  "summary": {"OK": 1, "WARNING": 0, "EXPIRED": 0, "ERROR": 0, "UNKNOWN": 0},
  "exit_code": 0
}
```

### 警告日数を変更（`--warn-days`）

```sh
# 残り 14 日以内なら WARNING（デフォルトは 30 日）
python3 cert_checker.py --warn-days 14 example.com
```

### その他のオプション

| オプション | 説明 |
|---|---|
| `--timeout SEC` | ネットワークタイムアウト秒数（デフォルト 10） |
| `--workers N` | 並列でチェックするドメイン数（デフォルト 8） |
| `--no-rdap` | ドメイン登録期限（RDAP）のチェックを省略 |
| `--version` | バージョン表示 |

## ステータスの意味

| ステータス | 意味 |
|---|---|
| `OK` | 証明書・ドメインとも残り日数が `--warn-days` より多い |
| `WARNING` | 証明書またはドメインの期限が `--warn-days` 日以内 |
| `EXPIRED` | 証明書またはドメインが期限切れ |
| `ERROR` | 証明書チェックに失敗（接続不可・名前解決失敗・証明書検証エラーなど） |
| `UNKNOWN` | 証明書は OK だが、RDAP で期限を取得できなかった |

ドメインごとのステータスは、証明書とドメイン登録のうち「より深刻なほう」です。

## 終了コード

| コード | 意味 |
|---|---|
| `0` | すべて OK（RDAP の UNKNOWN はエラー扱いしない） |
| `2` | WARNING または EXPIRED が 1 つ以上ある |
| `1` | チェックエラーがある（WARNING/EXPIRED はない）、またはドメインファイルを読めない |

WARNING/EXPIRED はエラーより優先されます（両方ある場合は `2`）。
なお、引数の誤りなど argparse の使い方エラーも終了コード `2` になります（このときはエラーメッセージが標準エラー出力に出ます）。

cron や CI では次のように使えます:

```sh
python3 cert_checker.py --file domains.txt || echo "要確認 (exit=$?)"
```

## テストの実行

テストは `unittest` のみを使い、ネットワーク呼び出しはすべてモックしているため、オフラインで実行できます。

```sh
python3 -m unittest discover -s tests -v
```

テストの対象: 日付パース（証明書形式 / RDAP の ISO 8601 形式）、残り日数とステータス判定、RDAP `events` の解析とエラー処理、証明書情報の抽出、ドメインファイルの解析、終了コード、CLI 出力（テーブル / JSON）。

## 現在の制限事項

- **RDAP の対応状況は TLD によって異なります。** `.com` / `.net` / `.org` などの gTLD は概ね対応していますが、
  ccTLD（`.jp` など）では RDAP サーバが提供されていない、または `expiration` イベントを返さないことが多く、その場合は `UNKNOWN` になります。
- 親ドメインへのフォールバックは「先頭のラベルを削る」単純な方式です。Public Suffix List は参照していないため、
  `www.example.co.jp` のようなケースでは正しく登録ドメインを特定できない場合があります。
- `rdap.org` はブートストラップ用の公開リダイレクタです。大量のドメインを短時間に問い合わせるとレート制限を受ける可能性があります。
- 証明書チェックは SNI 付きの TLS 接続で、サーバが提示したリーフ証明書のみを確認します（中間証明書の期限は個別にチェックしていません）。
- 検証に失敗した証明書の内容を読むために、CPython 内部の `ssl._ssl._test_decode_cert` を使用しています。
  これが使えない Python 実装では、検証失敗時は `ERROR` として報告されます。
- STARTTLS（SMTP/IMAP など）には対応していません。

## 今後のアイデア

- **通知**: WARNING/EXPIRED が出たときにメール（`smtplib`）や Slack（Incoming Webhook）で通知
- **定期実行**: cron / systemd timer での定期実行例の追加
  ```cron
  # 毎朝 9 時にチェックし、問題があればメール送信（例）
  0 9 * * * cd /path/to/cert-expiry-checker && python3 cert_checker.py --file domains.txt > /tmp/cert.log 2>&1 || mail -s "cert/domain expiry alert" you@example.com < /tmp/cert.log
  ```
- Public Suffix List を使った登録ドメインの正確な判定
- 中間証明書を含む証明書チェーン全体の期限チェック
- CSV / Prometheus メトリクス形式での出力
- ドメインごとに個別の `--warn-days` を設定できる設定ファイル（TOML など）

## ライセンス

MIT License（詳細は [LICENSE](LICENSE) を参照）
