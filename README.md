# go-certviewer
## Usage
Run cmd/main.go with one of the following flags

| Flag | Description|
|------|------------|
| -url | URL to fetch certificate chain from (excluding root) |
| -i   | Input certificate file in pem or der format |
| -d   | Input directory to fetch certificates from. <br>Will scan directory for applicable cert file ending with (.pem/.crt/.cert/.der) |

## URL Example
```bash
go run cmd/main.go -url google.com
```
![url flag example](/assets/screenshot_url_flag.png)