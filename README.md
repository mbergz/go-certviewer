# go-certviewer
## Usage
Run cmd/main.go with the following flags

| Flag | Description|
|------|------------|
| `-url` | URL to fetch certificate chain from |
| `-k`   | Insecure mode. Skip certificate validation (allow self-signed or unknown CAs). Used together with -url |
| `-i`   | Input certificate file path (absolute or relative) in pem or der format|
| `-d`   | Input directory path (absolute or relative) to fetch certificates from. <br>Will scan directory for applicable cert file ending with (.pem/.crt/.cer/.cert/.der) |

## URL Example
```bash
go run cmd/main.go -url example.com
```
![url flag example](/assets/screenshot_url_flag.png)