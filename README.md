# go-certviewer

## Install
```sh
go install github.com/mbergz/go-certviewer/cmd/go-certviewer@latest
```

## Usage
| Flag | Description|
|------|------------|
| `-url` | URL to fetch certificate chain from |
| `-k`   | Insecure mode. Skip certificate validation (allow self-signed or unknown CAs).<br>Used together with -url |
| `-cacert` | Optional CA certificate file for server verification |
| `-i`   | Input certificate file path (absolute or relative) in pem or der format|
| `-d`   | Input directory path (absolute or relative) to fetch certificates from.<br>Will scan directory for applicable cert file ending with (.pem/.crt/.cer/.cert/.der) |

## URL Example
```bash
go-certviewer -url example.com
```
![url flag example](/assets/screenshot_url_flag.png)