# net-mcp-readonly

[Türkçe](#türkçe) | [English](#english)

An MCP server that lets AI agents run **only policy-approved, read-only CLI
commands** (`show`, `display`) on network devices over SSH. Every call is
written to a hash-chained, append-only audit log.

Platforms: Nokia SR OS, Huawei VRP, Cisco IOS XR, Juniper Junos.

> **Status: v0.1, lab use.** Tested against an in-process mock SSH device
> only. It has **not** been run against real routers yet. See
> [Limits](#limits).

---

## Türkçe

### Ne işe yarar

Bir yapay zekâ ajanına (Claude Desktop, Claude Code ya da başka bir MCP
istemcisi) ağ cihazlarında arıza ayıklama yaptırmak istiyorsunuz ama ajanın
`configure`, `commit`, `reload` gibi bir şey göndermesini istemiyorsunuz.
`net-mcp-readonly` ajan ile cihaz arasına oturur:

1. Ajan bir komut ister (`run_show_command`).
2. Komut YAML politikasına göre değerlendirilir. Varsayılan **ret**tir.
3. Karar, cihaza bir bayt gitmeden önce denetim kaydına yazılır. Kayıt
   yazılamazsa komut gönderilmez.
4. İzin verilirse SSH ile bağlanılır, operasyonel istem (prompt) beklenir,
   sayfalama kapatılır, **normalize edilmiş** komut gönderilir, aynı istem
   geri gelene kadar çıktı okunur, oturum kapatılır.
5. Sonuç (süre, çıktı boyutu, çıktının SHA-256 özeti ya da hata) yine
   kayda yazılır; çıktının kendisi kayda yazılmaz.

### Araçlar (MCP tools)

| Araç | Ne yapar | Cihaza bağlanır mı |
|---|---|---|
| `list_devices` | Envanterdeki cihaz adlarını ve platformlarını listeler (IP adresi vermez) | Hayır |
| `check_command` | Komutun izinli olup olmadığını ve nedenini söyler | Hayır |
| `run_show_command` | İzinliyse komutu çalıştırır, çıktıyı döndürür | Evet |

Üç araç da `readOnlyHint: true`, `destructiveHint: false` olarak işaretlidir.

### Politika motoru

Her komut için sıra:

1. **Karakter denetimi.** Yalnızca yazdırılabilir ASCII. Satır sonu (`\n`,
   `\r`), sekme, kontrol karakterleri, Unicode (görünmez boşluk, benzer
   harfler) ve şu karakterler reddedilir:
   `` ; | & < > ` $ \ " ' # ! ? { } ( ) [ ] * ^ ~ % ``
   Bunlar desteklenen CLI'lardan en az birinde zincirleme, boru (pipe),
   yönlendirme, alıntılama, kaçış, yorum ya da yardım anlamı taşır.
2. **Normalizasyon.** Boşluklar teke indirilir; cihaza giden metin tam olarak
   budur. Kurallar büyük/küçük harf duyarsız eşleşir, ama komut özgün
   harfleriyle gönderilir (VRF ve route-policy adları harfe duyarlı olabilir).
3. **`deny_tokens`.** Komuttaki herhangi bir kelime listedeyse ret
   (`configure`, `system-view`, `commit`, `delete`, `reload`, `request`, ...).
4. **`deny_regex`.** Tüm komutla eşleşen desen varsa ret.
5. **`allow_prefixes`.** Kelime kelime önek eşleşmesi: `show interfaces`,
   `show interfaces brief`'e izin verir, `show interfacesx`'e vermez.
6. **`allow_regex`.** Tüm komutla eşleşmeli (otomatik `^...$`).
7. Hiçbiri değilse ret.

Ret her zaman izni yener. **Kısaltmalar açılmaz:** `sh ip route` reddedilir,
çünkü `sh` ≠ `show`. Bu bilinçli bir tercih; kısaltmaları güvenle açmak her
CLI'ın komut ağacını bilmeyi gerektirir.

Örnek politika: [`examples/policy.yaml`](examples/policy.yaml). Bir komutu
sunucuyu çalıştırmadan denemek için:

```powershell
net-mcp-readonly check -policy examples/policy.yaml -platform iosxr "show bgp summary"
```

İzinliyse çıkış kodu 0, değilse 1. Politika değişikliklerini CI'da sınamak
için kullanılabilir.

### Kurulum

Go 1.26 veya üstü gerekir.

```powershell
git clone https://github.com/ogzhncnmr/net-mcp-readonly
```

```powershell
cd net-mcp-readonly; go build -o net-mcp-readonly.exe ./cmd/net-mcp-readonly
```

```powershell
go test ./...
```

### Yapılandırma

**1. Envanter** — [`examples/inventory.yaml`](examples/inventory.yaml).
Dosyada parola yoktur; `credentials` alanı sırrın nerede olduğunu gösterir:

- `env:NETMCP_LAB` → `NETMCP_LAB_USERNAME` ve `NETMCP_LAB_PASSWORD`
  ve/veya `NETMCP_LAB_KEY_FILE` (+ `NETMCP_LAB_KEY_PASSPHRASE`)
- `keyring:SERVIS/KULLANICI` → işletim sistemi anahtarlığı (Windows
  Credential Manager, macOS Keychain, Linux Secret Service)

Anahtarlığa parola kaydetmek için (parola ekranda görünmez):

```powershell
.\net-mcp-readonly.exe keyring-set net-mcp-readonly netops-ro
```

**2. known_hosts zorunludur.** Ana makine anahtarı doğrulamasını kapatan bir
seçenek yoktur. OpenSSH `known_hosts` biçiminde bir dosya hazırlayın
(ör. `ssh-keyscan` ile) ve parmak izlerini başka bir kanaldan doğrulayın.

**3. Cihaz tarafı:** Ajan için cihazda **salt okunur yetkili ayrı bir hesap**
açın (IOS XR task group, Junos `read-only` login class, VRP düşük seviye
kullanıcı, SR OS profil). Bu sunucu ikinci savunma hattıdır, cihazdaki AAA'nın
yerini tutmaz.

### Claude Desktop

`claude_desktop_config.json` (Windows: `%APPDATA%\Claude\`, macOS:
`~/Library/Application Support/Claude/`). Örnek:
[`examples/claude_desktop_config.json`](examples/claude_desktop_config.json)

```json
{
  "mcpServers": {
    "net-readonly": {
      "command": "C:\\tools\\net-mcp-readonly.exe",
      "args": ["serve",
        "-policy", "C:\\netmcp\\policy.yaml",
        "-inventory", "C:\\netmcp\\inventory.yaml",
        "-audit", "C:\\netmcp\\audit.jsonl"]
    }
  }
}
```

Parolayı bu dosyanın `env` bölümüne yazmak mümkündür ama dosya düz metindir;
`keyring:` tercih edin.

### Claude Code

```powershell
claude mcp add net-readonly -- C:\tools\net-mcp-readonly.exe serve -policy C:\netmcp\policy.yaml -inventory C:\netmcp\inventory.yaml -audit C:\netmcp\audit.jsonl
```

### Denetim kaydı

JSON Lines, yalnızca sona eklenir (Unix'te dosya `0600` izniyle oluşturulur). Her satırda:
`seq`, `time`, `event` (`check` / `deny` / `allow` / `result`), `actor`
(sunucuyu çalıştıran OS kullanıcısı ya da `-actor`), `client` (MCP istemcisinin
bildirdiği ad/sürüm), `device`, `platform`, `command` (ham), `normalized`,
`allowed`, `rule`, `reason`, sonuçta `duration_ms`, `output_bytes`,
`output_sha256` ya da `error`; ve `prev_hash` / `hash` zinciri.

```powershell
.\net-mcp-readonly.exe verify-audit C:\netmcp\audit.jsonl
```

Sunucu açılışta mevcut kaydı doğrular; zincir bozuksa başlamaz.

### Güvenlik modeli

Korunduğu şeyler:

- Ajanın izin listesi dışında komut göndermesi (varsayılan ret, ret önceliği).
- `;`, `|`, satır sonu, `&&`, `` ` ``, `$()` ile zincirleme/kaçış; Unicode
  benzer harf ve görünmez karakter hileleri. Bunlar için 69 adlandırılmış saldırı örneği,
  yasak karakterlerin tek tek sınanması ve bir fuzz testi var.
- Bilinmeyen/değişmiş ana makine anahtarı (zorunlu `known_hosts`).
- Mod değişikliği: girişte görülen operasyonel istem komuttan sonra birebir
  geri gelmezse oturum kapatılır ve hata kaydedilir.
- Kaydedilmeyen komut: karar yazılamazsa komut gönderilmez; sonuç
  yazılamazsa çıktı ajana verilmez.
- Kayıtta sonradan düzenleme, silme, yer değiştirme (hash zinciri).

### Sınırlar

Bunları bilerek kullanın:

- **Gerçek cihazda denenmedi.** İstem desenleri ve sayfalama komutları
  (`terminal length 0`, `set cli screen-length 0`,
  `screen-length 0 temporary`, `environment no more`) üretici CLI
  alışkanlıklarına göre yazıldı ve yalnızca sahte cihazla sınandı. Yazılım
  sürümünüz farklıysa cihaz bazında `paging_command` ile değiştirin.
- **SR OS MD-CLI:** düzenleme modu istemin bir üst satırında gösterildiği
  için istem denetimi MD-CLI'da yapılandırma modunu ayırt edemez; orada
  koruma yalnızca politikaya dayanır.
- **`show` her zaman zararsız değildir.** `show running-config` /
  `show configuration` / `display current-configuration` parola özetleri,
  SNMP community'leri gibi sırlar içerebilir ve bu çıktı modele gider. Bazı
  `show` komutları cihazda yük oluşturur. Mümkünse dar bir izin listesi
  kullanın.
- **Cihaz çıktısı güvenilmez veridir.** Arayüz açıklaması, BGP community
  ya da log satırı içine yazılmış talimatlar modele ulaşır (prompt
  injection). Sunucu çıktıyı temizlemez.
- **Kimlik:** stdio üzerinde kullanıcı doğrulaması yoktur. `actor` sunucuyu
  çalıştıran OS kullanıcısıdır; `client` adını MCP istemcisi kendisi bildirir
  ve sahte olabilir.
- **Kayıt yerel bir dosyadır.** Zincir düzenlemeyi yakalar ama dosyanın
  sonundan satır silinmesini ya da tüm dosyanın yeniden yazılmasını
  yakalayamaz. Önemliyse kaydı makine dışına (syslog, WORM depolama) aktarın.
- Boru, tırnak ve kısaltma desteklenmediği için bazı meşru komutlar
  yazılamaz (ör. `show configuration | display set`).
- Sayfalama komutu politikadan geçmez; operatörün envanterde verdiği sabit
  bir komuttur.
- Her çağrıda yeni SSH oturumu açılır (basit ama yavaş). Hız sınırı yoktur,
  yalnızca eşzamanlı oturum sınırı (`-max-concurrent`, varsayılan 4).

### İlgili

- [doupass](https://github.com/ogzhncnmr/doupass) — ajanlar için Go ile
  yazılmış politika motoru ve hash zincirli denetim kaydı. Bu proje aynı
  fikri ağ CLI'ına uygular; doğrudan bir entegrasyon yoktur.
- [mtu-stack](https://github.com/ogzhncnmr/mtu-stack)

---

## English

### What it does

You want an AI agent (Claude Desktop, Claude Code or any MCP client) to help
troubleshoot network devices, but you do not want it to send `configure`,
`commit` or `reload`. `net-mcp-readonly` sits between the agent and the
devices:

1. The agent asks to run a command (`run_show_command`).
2. The command is evaluated against a YAML policy. The default is **deny**.
3. The decision is written to the audit log before any byte reaches the
   device. If it cannot be written, nothing is sent.
4. If allowed: SSH in, wait for the operational prompt, disable paging, send
   the **normalized** command, read until the same prompt returns,
   disconnect.
5. The outcome (duration, output size, SHA-256 of the output, or the error)
   is logged too. The output itself is not stored in the log.

### Tools

| Tool | Purpose | Contacts device |
|---|---|---|
| `list_devices` | Device names and platforms (no IP addresses) | No |
| `check_command` | Would this command be allowed, and why | No |
| `run_show_command` | Run an allowed command and return its output | Yes |

All three are annotated `readOnlyHint: true`, `destructiveHint: false`.

### Policy engine

For every command, in order:

1. **Character check.** Printable ASCII only. Line breaks, tabs, control
   characters, any non-ASCII (zero-width spaces, homoglyphs) and these
   characters are rejected:
   `` ; | & < > ` $ \ " ' # ! ? { } ( ) [ ] * ^ ~ % ``
   Each has a chaining, piping, redirection, quoting, escaping, comment or
   help meaning on at least one supported CLI.
2. **Normalization.** Whitespace collapsed; this exact string is what the
   device receives. Rules match case-insensitively, but the command keeps
   its original case (VRF and route-policy names can be case-sensitive).
3. **`deny_tokens`.** Any word on the list → deny.
4. **`deny_regex`.** Full-match pattern → deny.
5. **`allow_prefixes`.** Word-by-word prefix: `show interfaces` allows
   `show interfaces brief`, not `show interfacesx`.
6. **`allow_regex`.** Must match the whole command (anchored automatically).
7. Otherwise → deny.

Deny always beats allow. **Abbreviations are not expanded:** `sh ip route`
is denied because `sh` is not `show`. Expanding abbreviations safely would
require each CLI's full command tree.

Example policy: [`examples/policy.yaml`](examples/policy.yaml). Try a command
without starting the server:

```powershell
net-mcp-readonly check -policy examples/policy.yaml -platform iosxr "show bgp summary"
```

Exit code 0 means allowed, 1 means denied, so policy changes can be tested in
CI.

### Install

Requires Go 1.26 or newer.

```powershell
git clone https://github.com/ogzhncnmr/net-mcp-readonly
```

```powershell
cd net-mcp-readonly; go build -o net-mcp-readonly.exe ./cmd/net-mcp-readonly
```

```powershell
go test ./...
```

### Configuration

**1. Inventory** — [`examples/inventory.yaml`](examples/inventory.yaml). No
secrets in the file; `credentials` points to where they live:

- `env:NETMCP_LAB` → `NETMCP_LAB_USERNAME` plus `NETMCP_LAB_PASSWORD`
  and/or `NETMCP_LAB_KEY_FILE` (+ `NETMCP_LAB_KEY_PASSPHRASE`)
- `keyring:SERVICE/USER` → OS keyring (Windows Credential Manager, macOS
  Keychain, Secret Service on Linux)

Store a password in the keyring (input is not echoed):

```powershell
.\net-mcp-readonly.exe keyring-set net-mcp-readonly netops-ro
```

**2. known_hosts is mandatory.** There is no switch to skip host key
verification. Provide an OpenSSH `known_hosts` file (e.g. from
`ssh-keyscan`) and verify fingerprints out of band.

**3. On the device:** give the agent its **own read-only account**
(IOS XR task group, Junos `read-only` login class, low VRP user level, SR OS
profile). This server is a second line of defense, not a replacement for
device AAA.

### Claude Desktop

Edit `claude_desktop_config.json` (Windows: `%APPDATA%\Claude\`, macOS:
`~/Library/Application Support/Claude/`). See
[`examples/claude_desktop_config.json`](examples/claude_desktop_config.json)
and the JSON in the Turkish section above. Passwords can go into an `env`
block there, but that file is plain text; prefer `keyring:`.

### Claude Code

```powershell
claude mcp add net-readonly -- C:\tools\net-mcp-readonly.exe serve -policy C:\netmcp\policy.yaml -inventory C:\netmcp\inventory.yaml -audit C:\netmcp\audit.jsonl
```

### Audit log

JSON Lines, append-only (created with mode `0600` on Unix). Each line has `seq`,
`time`, `event` (`check` / `deny` / `allow` / `result`), `actor` (OS user
running the server, or `-actor`), `client` (name/version reported by the MCP
client), `device`, `platform`, raw `command`, `normalized`, `allowed`,
`rule`, `reason`; results add `duration_ms`, `output_bytes`,
`output_sha256` or `error`; plus the `prev_hash` / `hash` chain.

```powershell
.\net-mcp-readonly.exe verify-audit C:\netmcp\audit.jsonl
```

The server verifies the existing log at startup and refuses to start if the
chain is broken.

### Security model

What it protects against:

- The agent sending anything outside the allow list (default deny, deny wins).
- Chaining and escapes via `;`, `|`, line breaks, `&&`, backticks, `$()`;
  Unicode homoglyph and invisible-character tricks. Covered by 69 named attack
  test cases, a per-character test and a fuzz test.
- Unknown or changed host keys (mandatory `known_hosts`).
- Mode changes: if the exact operational prompt seen at login does not come
  back after the command, the session is closed and the error logged.
- Unlogged commands: if the decision cannot be logged, nothing is sent; if
  the result cannot be logged, the output is withheld.
- Editing, deleting or reordering past log entries (hash chain).

### Limits

Use it knowing these:

- **Not yet tested on real devices.** Prompt patterns and paging commands
  (`terminal length 0`, `set cli screen-length 0`,
  `screen-length 0 temporary`, `environment no more`) follow vendor CLI
  conventions and were exercised only against the mock device. Override
  `paging_command` per device if your release differs.
- **SR OS MD-CLI** shows the edit mode on the line above the prompt, so the
  prompt check cannot detect configuration mode there; only the policy
  protects you.
- **`show` is not always harmless.** `show running-config`,
  `show configuration` and `display current-configuration` can contain
  secret hashes and SNMP communities, and that output goes to the model.
  Some `show` commands are expensive on the device. Prefer a narrow allow
  list.
- **Device output is untrusted.** Text in interface descriptions, BGP
  communities or log lines reaches the model (prompt injection). The server
  does not sanitize output.
- **Identity:** there is no user authentication on stdio. `actor` is the OS
  user running the server; `client` is self-reported by the MCP client and
  can be spoofed.
- **The log is a local file.** The chain catches edits but not truncation of
  trailing lines or a full rewrite. Forward it off the host (syslog, WORM
  storage) if that matters.
- No pipes, quotes or abbreviations, so some legitimate commands cannot be
  expressed (e.g. `show configuration | display set`).
- The paging command bypasses the policy; it is a fixed string set by the
  operator in the inventory.
- One SSH session per call (simple, not fast). No rate limiting beyond the
  concurrent-session cap (`-max-concurrent`, default 4).

### Related

- [doupass](https://github.com/ogzhncnmr/doupass) — a Go policy engine for
  agents with a hash-chained audit log. This project applies the same idea to
  network CLIs; there is no direct integration.
- [mtu-stack](https://github.com/ogzhncnmr/mtu-stack)

### Development

```powershell
go vet ./...
```

```powershell
go test ./...
```

```powershell
go test -run='^$' -fuzz=FuzzEvaluate -fuzztime=30s ./internal/policy/
```

Layout:

```
cmd/net-mcp-readonly/   CLI: serve, check, verify-audit, keyring-set
internal/policy/        policy engine + attack tests + fuzz test
internal/audit/         hash-chained JSON Lines log
internal/device/        inventory, credentials, SSH runner
internal/mockdevice/    in-process SSH server used by tests
internal/server/        MCP tools, end-to-end tests
examples/               policy, inventory, Claude Desktop config
```

## License

MIT — see [LICENSE](LICENSE).
