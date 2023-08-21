module github.com/AthenZ/athenz-client-sidecar/v2

go 1.20

replace github.com/AthenZ/athenz => github.com/AthenZ/athenz v1.11.32

require (
	github.com/AthenZ/athenz v1.11.32
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang-jwt/jwt/v5 v5.0.0
	github.com/kpango/fastime v1.1.9
	github.com/kpango/gache v1.2.8
	github.com/kpango/glg v1.6.15
	github.com/kpango/ntokend v1.0.12
	github.com/pkg/errors v0.9.1
	golang.org/x/sync v0.3.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/ardielle/ardielle-go v1.5.2 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	golang.org/x/sys v0.10.0 // indirect
)
