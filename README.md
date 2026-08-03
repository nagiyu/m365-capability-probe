# m365-capability-probe

Entra のアプリ登録 (テナント ID / クライアント ID / クライアント シークレット) を 1 つ受け取り、
**そのアプリが Microsoft 365 に対して実際に何に届くか** を報告する小さなコマンドライン ツールです。
アクセス許可の一覧が約束しているように見えるものではなく、実測を報告します。

答えるのは 2 つの問いです。

1. **アプリ自身として見えるものと、利用者として見えるものは同じか。** 同一のファイルを 1 回の実行で
   2 回読みます ― 1 回はアプリ単独 (app-only) のトークンで、もう 1 回はサインインした利用者の代理
   (delegated) で。2 つの答えを並べて出します。
2. **届かなかったとき、正確に何が返ってきたか。** 拒否は測定値として記録します。ID プロバイダーや
   Graph が実際に返したエラーコードつきで。ここでの `403` は結果であって、不具合の報告ではありません。

すべて `HttpClient` を直接使っています。Graph SDK は使いません ― **どの URL にどのヘッダを付けて
叩いたかが読めて、手で再現できること** がこのツールの価値であり、SDK はそれを隠すからです。あわせて、
Graph と、あとから足すかもしれない SharePoint REST とを 1 つの経路で扱えます。

実テナントに対して動かしたところ、**アプリの API アクセス許可画面から立てた妥当な予測が、3 つとも
外れました。** その顛末は **[docs/findings.md](docs/findings.md)** にまとめてあります。この種の
ツールを持つ理由の、一番短い説明になっています。

## やらないこと

保護されたファイルの復号、サイト全体の走査、スループットの測定、差分の追跡はしません。失敗する
呼び出しを成功させようともしません。**測定対象のいくつかは失敗することが期待値** であり、それらが
成功し始めた実行は、逆向きの所見です。

## 必要なもの

- .NET 10 SDK
- 調べたいテナントの Entra アプリ登録
- ドキュメント ライブラリにファイルが 1 つ以上ある SharePoint サイト
- そのサイトを見られる、管理者ではないアカウント (委任側で使います)

## アプリ登録の設定

次の API アクセス許可を付与し、管理者の同意を与えてください。

| API | アクセス許可 | 種類 |
| --- | --- | --- |
| Microsoft Graph | `Sites.Read.All` | アプリケーション |
| Microsoft Graph | `Sites.Read.All` | 委任 |
| SharePoint | `Sites.Read.All` | アプリケーション |

**Azure Rights Management には意図的に何も付与しないでください。** また、SharePoint の
`Sites.Read.All` を **委任** として付与しないでください。この 2 つの欠落こそが `auth` サブコマンドの
測定対象です。埋めてしまうと、このツールが報告できることは増えるのではなく減ります。

**認証** で「パブリック クライアント フローを許可する」を **はい** にしてください。委任側は
デバイス コード フローを使います。これはパブリック クライアント フローなので、**クライアント
シークレットは一切使いません** ― シークレットを使うのは app-only 側だけです。

## 設定

キーは 6 つです。

| キー | 内容 |
| --- | --- |
| `TenantId` | ディレクトリ (テナント) ID |
| `ClientId` | アプリケーション (クライアント) ID |
| `ClientSecret` | クライアント シークレット |
| `SiteUrl` | `https://<host>/sites/<name>` |
| `FilePath` | サイトの既定のドキュメント ライブラリ内のパス。例 `/test.docx` |
| `DelegatedUserHint` | 委任側で使う利用者のサインイン名 |

**`FilePath` にライブラリ名自体は含めません。** この値は `/drive/root:` に付け足されますが、そこは
すでにサイトの既定のドキュメント ライブラリのルートです。したがってライブラリ直下にあるファイルは
`/Shared Documents/test.docx` ではなく、単に `/test.docx` です。ライブラリ名を頭に付けると、
ライブラリの **中にある** 同名のフォルダを探しに行って `404` が返ります。サブフォルダはパスに
含めます: `/drafts/q3.docx`。

他の 5 つのキーはそのまま読まれます。分解されるのは `SiteUrl` だけで、ホスト名 (SharePoint の
スコープになります) とサーバー相対パス (サイトを解決します) に分けられます。

設定は 5 つの層から読まれ、**後の層が勝ちます**。

1. `src/CapabilityProbe.Cli/appsettings.json` ― コミット済み。キーだけあって値は空。値を持つためでは
   なく、スキーマを自己文書化するために存在します
2. `appsettings.local.json` ― git 管理外。`appsettings.json` の隣に置きます
3. **user-secrets** ― `ClientSecret` の置き場所として想定しているのはここです
4. `PROBE_` 接頭辞つきの環境変数。例 `PROBE_ClientSecret`
5. コマンドライン引数。例 `--ClientSecret=...`

推奨する設定手順:

```bash
cd src/CapabilityProbe.Cli
dotnet user-secrets set "TenantId"          "<テナントの GUID>"
dotnet user-secrets set "ClientId"          "<クライアントの GUID>"
dotnet user-secrets set "ClientSecret"      "<シークレットの値>"
dotnet user-secrets set "SiteUrl"           "https://contoso.sharepoint.com/sites/probe"
dotnet user-secrets set "FilePath"          "/test.docx"
dotnet user-secrets set "DelegatedUserHint" "reader@contoso.com"
```

このツールは何かをする前に設定を検証します。足りないキーは名前で、それが塞いでいるサブコマンドと
ともに並べられ、実行はそこで終わります ― 例外も投げなければ、途中まで観測することもしません。

```
Missing or invalid keys:
  ClientSecret       missing - client secret; keep it in user-secrets, not in a committed file
                     blocks: auth, access
  FilePath           missing - path inside the site's default document library, without the library's own name, e.g. /test.docx
                     blocks: access

Subcommand readiness:
  auth     ready
  access   needs FilePath
```

## 実行

```bash
dotnet run --project src/CapabilityProbe.Cli -- auth
dotnet run --project src/CapabilityProbe.Cli -- access
```

任意のキーは実行ごとに上書きできます。

```bash
dotnet run --project src/CapabilityProbe.Cli -- access --FilePath="/drafts/q3.docx"
```

どちらのサブコマンドも、表を出力すると同時に、同じ内容を
`reports/<サブコマンド>-<タイムスタンプ>.json` に書きます。

### `auth`

3 つの audience に対して 2 つのモードでトークンを要求し、6 通りの結果を報告します。トークンは何の
呼び出しにも使いません。このサブコマンドが測るのは **アプリが何を保持しているか** だけです。

| audience | スコープ |
| --- | --- |
| Graph | `https://graph.microsoft.com/.default` |
| SharePoint | `https://<SiteUrl のホスト名>/.default` |
| Azure RMS | `https://aadrm.com/.default` |

SharePoint のスコープは `SiteUrl` のホスト名から組み立てます。このツールはテナントの一覧を内部に
持ちません。

上記の設定であれば、期待される形はこうなります。

| audience | app-only | delegated |
| --- | --- | --- |
| Graph | `Sites.Read.All` を保持 | `Sites.Read.All` を保持 |
| SharePoint | `Sites.Read.All` を保持 | `Sites.Read.All` を保持 ― **下記参照** |
| Azure RMS | **何も保持しない** | **何も保持しない** ― 何も付与していない |

そこから外れたセルには `[!]` が付きます。

このうち 2 つのセルは立ち止まる価値があります。どちらも、アクセス許可の画面から予測されるものでは
ありません。

**SharePoint / delegated は、付与されていない権限を保持しています。** このアプリ登録に SharePoint の
**委任** アクセス許可は 1 つもありません ― あるのはアプリケーションのものだけです。にもかかわらず
委任側は、`aud` が `00000003-0000-0ff1-ce00-000000000000` (SharePoint Online) で
`scp: Sites.Read.All User.Read` を持つトークンを受け取ります。これはこのアプリの **Microsoft Graph**
の委任付与と完全に一致します。Graph の `Sites.Read.All` への同意が SharePoint にも届いています。
API アクセス許可の画面にそう書いてある箇所はありません。トークンを取って中を見て初めて現れます。

**Azure RMS / app-only は、何もできないトークンを発行されます。** RMS のアクセス許可は両方向とも
付与していません。委任側は `AADSTS65001` で明確に拒否されますが、**app-only 側は成功し**、`roles` も
`scp` も持たないトークンが返ります。両者が食い違うのは `.default` の意味が異なるからです。サインイン
した利用者にとっては「すでに同意済みのスコープ全部」で、同意が 0 個ならエラーになります。
クライアント資格情報にとっては「割り当て済みのアプリ ロール全部」で、割り当てが 0 個なら単に空の
トークンになります。

**トークンが発行されたことと、アプリが何かできることは同じではありません。** Entra は、アプリに
何も付与されていないリソースに対してもトークンを渡します ― アプリ ロールが 1 つも割り当てられて
いないリソースへのクライアント資格情報の要求も、そのリソースのサービス プリンシパルがテナントに
存在する限り成功します ― そして返るトークンは roles も scopes も持ちません。有効ではあるが、それを
使った呼び出しはすべて拒否されるトークンです。発行の有無だけで判断すると、触れないリソースに
届いているとそのアプリを報告してしまいます。それこそ、このツールが防ぐために存在する間違いです。

そこで各セルは両方を報告します: トークンが返ってきたか、そして **それが何を持っているか**。レポートは
トークンのペイロードから `roles` と `scp` のクレームを読んで出力します。これらのクレームは
**読むだけで、検証はしません**。このツールはどのトークンの受け手でもなく、トークンに基づく信頼の
判断を一切しないので、署名の検証は誰も問うていない問いに答えることになります。そのための
トークン処理ライブラリも導入していません。

拒否されたセルにはエラーコードがそのまま載ります。**「このアプリにそれが付与されていない」と
「そのリソースがこのテナントに存在しない」を分けられるのはコードだけ** だからです ― 失敗した
トークン要求としては、どちらも同じ形をしています。

所要時間の欄は、資格情報が自身のメモリ キャッシュから答えた場合に `cached` と表示します。キャッシュ
ヒットが「非常に速いネットワーク往復」と読み違えられないようにするためです。

委任のサインインはデバイス コード フローです。コード、サインイン URL、そして設定した
`DelegatedUserHint` は、いずれもプロンプトの前に表示されます。意図した閲覧者ではなく管理者アカウント
でサインインすると、この比較は黙って無意味になるので、使うべきアカウントを画面に出しています。
サインインは Graph に対して 1 回だけ行い、以降の audience はサイレントで要求します。そのため同意の
ない audience は、2 回目のプロンプトで実行を止めることなく、拒否として返ります。

### `access`

同一ファイルの権限一覧を 2 回 ― app-only と delegated で ― **1 回の実行のうちに** 読みます。両方が
同じ瞬間を記述するようにするためです。どちらの経路も同じ 3 つの呼び出しを辿ります。

```
GET /v1.0/sites/{ホスト名}:{サーバー相対パス}            -> サイト ID
GET /v1.0/sites/{サイトID}/drive/root:/{ファイルパス}    -> アイテム ID
GET /v1.0/sites/{サイトID}/drive/items/{アイテムID}/permissions
```

パスによる指定は、次の URL を組み立てる前に必ず ID へ解決します。Graph のパス指定はコロン区間を
1 つしか使えず、2 つつないだ URL は `400` で弾かれます。

モードごとに、各呼び出しの HTTP ステータス、権限エントリの件数、そこに現れたプリンシパルの種類
(`user` / `group` / `siteGroup` / `application` / `link:…`)、所要ミリ秒を記録します。発行した呼び出しの
全一覧 ― URL、送ったヘッダ、ステータス、所要時間、Graph のエラーコード ― は独立した表として出力
されます。

サイトの **閲覧者** でしかない委任ユーザーの場合、どちらの経路もサイトとファイルの解決には成功します。
差が出るのは最後の呼び出しで、しかもそれは拒否という形では現れません。

```
| mode      | site   | item   | permissions | entries | principal kinds                            |
| app-only  | 200 OK | 200 OK | 200 OK      | 4       | sharePointGroup, siteGroup, siteUser, user |
| delegated | 200 OK | 200 OK | 200 OK      | 0       | -                                          |
```

**Graph は委任の呼び出し元を拒否しません。空のコレクションつきで `200 OK` を返します。** 権限エントリ
は呼び出し元が見てよいものだけに絞られ、1 件も見てよいものがない呼び出し元には「成功、中身は空」と
告げられます ― app-only 側が 4 件見えているのと、同じアイテムの、同じ瞬間にです。

これは `403` が返るより価値のある観測です。捕まえるのが難しい間違いだからです。**ステータス コードには
「このファイルは誰とも共有されていない」と「このファイルの共有は自分に見せてもらえない」を分ける
ものが何もありません。** 委任側の答えだけを読んで「共有されていない」と結論するコードは、真逆の結果を
得ます。両方の経路を 1 回の実行でまとめて叩くことが、この隙間を見えるようにしています。

委任のトークンの所要時間には、人がデバイス コードのサインインを終えるまでの待ち時間が含まれます。
1 分半をサービスの応答時間として提示しないよう、レポートはその旨を明記します。

## 出力の読み方

レポートの各行は 3 つのものを持ちます。

- **主張 (claim)** ― 実行の前に立てた言明。拒否されるという主張も含みます
- **観測 (observed)** ― 実際に返ってきたもの
- **判定 (verdict)** ― `Ok` / `Failed` / `NotRun`

`Ok` は **観測が主張と一致した** ことを意味します。「呼び出しが成功した」ではありません。拒否を
主張する行では、`403` が `Ok` です。

`NotRun` があるのは、*「そこまで到達しなかったので見ていない」* に固有の値を与えるためです。サイトが
解決できなかったなら、権限の読み取りは黙って合格したのではなく、起きなかったのです。空欄は合格と
読めてしまいますが、`NotRun` はそう読めません。

終了コード: `0` すべての主張が成立、`1` 主張が覆された、`2` 走らなかったものがある、`64` 使い方の
誤り、`78` 設定が不完全、`130` 中断。

## 構成

```
src/CapabilityProbe.Cli/
  Program.cs          サブコマンドの分岐
  appsettings.json    キー名のみ、値は空
  Configuration/      ProbeOptions, ProbeOptionsLoader
  Auth/               ProbeMode, ProbeAudience, ScopeResolver, ITokenSource,
                      AppOnlyTokenSource, DelegatedTokenSource, AuthErrorCode, TokenClaims
  Http/               ProbeHttpClient ― ステータスと本文を返し、応答で例外を投げない
  Probes/             AuthProbe, AccessProbe
  Reporting/          Verdict, Observation, ProbeReport, ConsoleReportWriter, JsonReportWriter
```

コード内のコメントと識別子は英語です。

## 秘密の扱い

秘密は 1 つも追跡されていません。`appsettings.local.json`、`reports/`、`*.pfx`、
`Properties/launchSettings.json` は git 管理外です。トークンはメモリ上にのみ保持されます。記録される
要求ヘッダには、ベアラー トークンの値ではなくその長さが載ります。

## ライセンス

MIT ― [LICENSE](LICENSE) を参照してください。
