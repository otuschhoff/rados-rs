package p12qualcontract

import "fmt"

const (
	MinimumGo = "go1.26.8"
	LatestGo  = "go1.27.1"
	Module    = "github.com/otuschhoff/go-librados"

	ImageAMD64  = "quay.io/ceph/ceph@sha256:09ee90f6f3e0c7b9954f71d214ee05e9bbaaaea3716b1dd619603283b829f8b8"
	ImageARM64  = "quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa"
	Staticcheck = "v0.8.1"
	Govulncheck = "v1.1.4"
)

type Pins struct {
	ImageAMD64  string
	ImageARM64  string
	Staticcheck string
	Govulncheck string
}

type Spec struct {
	ID        string
	Command   string
	Toolchain string
	Platform  string
}

func DefaultPins() Pins {
	return Pins{ImageAMD64: ImageAMD64, ImageARM64: ImageARM64, Staticcheck: Staticcheck, Govulncheck: Govulncheck}
}

func Checks(pins Pins, releaseVersion string) []Spec {
	specs := []Spec{
		{"minimum-unit", "CGO_ENABLED=0 GOTOOLCHAIN=" + MinimumGo + " go test ./...", MinimumGo, "host"},
		{"minimum-build", "CGO_ENABLED=0 GOTOOLCHAIN=" + MinimumGo + " go build ./...", MinimumGo, "host"},
		{"minimum-vet", "CGO_ENABLED=0 GOTOOLCHAIN=" + MinimumGo + " go vet ./...", MinimumGo, "host"},
		{"go-version-latest", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go version", LatestGo, "host"},
		{"latest-unit", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go test ./...", LatestGo, "host"},
		{"latest-build", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go build ./...", LatestGo, "host"},
		{"latest-vet", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go vet ./...", LatestGo, "host"},
		{"cross-linux-amd64", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " GOOS=linux GOARCH=amd64 go build ./...", LatestGo, "linux/amd64"},
		{"cross-linux-arm64", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " GOOS=linux GOARCH=arm64 go build ./...", LatestGo, "linux/arm64"},
		{"cross-darwin-amd64", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " GOOS=darwin GOARCH=amd64 go build ./...", LatestGo, "darwin/amd64"},
		{"cross-darwin-arm64", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " GOOS=darwin GOARCH=arm64 go build ./...", LatestGo, "darwin/arm64"},
		{"race", "CGO_ENABLED=1 GOTOOLCHAIN=" + LatestGo + " go test -race ./...", LatestGo, "host"},
		{"staticcheck", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go run honnef.co/go/tools/cmd/staticcheck@" + pins.Staticcheck + " ./...", LatestGo, "host"},
		{"govulncheck", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go run golang.org/x/vuln/cmd/govulncheck@" + pins.Govulncheck + " ./...", LatestGo, "host"},
		{"module-verify", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go mod verify", LatestGo, "host"},
		{"no-cgo", "test -z \"$(CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go list -deps -f '{{if .CgoFiles}}{{.ImportPath}}{{end}}' ./...)\"", LatestGo, "host"},
		{"reachable-dependencies", "test \"$(CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}' . | sort -u)\" = \"$(printf '%s\\n' 'github.com/jcmturner/aescts/v2 v2.0.0' 'github.com/jcmturner/gofork v1.7.6' 'github.com/otuschhoff/gokrb5/v8 v8.5.3' 'golang.org/x/crypto v0.56.0')\"", LatestGo, "host"},
		{"api-inventory", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go run ./tools/p12-qualify -check-inventory docs/p00/api-inventory.csv", LatestGo, "host"},
		{"examples-build", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go build ./examples/...", LatestGo, "host"},
	}
	for phase := 3; phase <= 11; phase++ {
		specs = append(specs, Spec{fmt.Sprintf("verify-p%02d", phase), fmt.Sprintf("CGO_ENABLED=0 GOTOOLCHAIN=%s go run ./tools/p%02d-verify", LatestGo, phase), LatestGo, "host"})
	}
	releaseCommand := "rm -rf \"$P12_TMP/release-1\" \"$P12_TMP/release-2\" && CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go run ./tools/p12-release -root . -out \"$P12_TMP/release-1\" -version " + shellQuote(releaseVersion) + " && CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " go run ./tools/p12-release -root . -out \"$P12_TMP/release-2\" -version " + shellQuote(releaseVersion) + " && diff -rq \"$P12_TMP/release-1\" \"$P12_TMP/release-2\""
	return append(specs, Spec{"deterministic-release", releaseCommand, LatestGo, "host"})
}

func Runtimes(pins Pins) []Spec {
	return []Spec{
		{"runtime-darwin-arm64", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '-X main.cgoEnabled=false' -o \"$P12_TMP/platform-probe-darwin-arm64\" ./integration/p12/platform-probe && \"$P12_TMP/platform-probe-darwin-arm64\"", LatestGo, "darwin/arm64"},
		{"runtime-darwin-amd64", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags '-X main.cgoEnabled=false' -o \"$P12_TMP/platform-probe-darwin-amd64\" ./integration/p12/platform-probe && /usr/bin/arch -x86_64 \"$P12_TMP/platform-probe-darwin-amd64\"", LatestGo, "darwin/amd64"},
		{"runtime-linux-arm64", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '-X main.cgoEnabled=false' -o \"$P12_TMP/platform-probe-linux-arm64\" ./integration/p12/platform-probe && docker run --rm --platform linux/arm64 -v \"$P12_TMP:/work:ro\" " + shellQuote(pins.ImageARM64) + " /work/platform-probe-linux-arm64", LatestGo, "linux/arm64"},
		{"runtime-linux-amd64", "CGO_ENABLED=0 GOTOOLCHAIN=" + LatestGo + " GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-X main.cgoEnabled=false' -o \"$P12_TMP/platform-probe-linux-amd64\" ./integration/p12/platform-probe && docker run --rm --platform linux/amd64 -v \"$P12_TMP:/work:ro\" " + shellQuote(pins.ImageAMD64) + " /work/platform-probe-linux-amd64", LatestGo, "linux/amd64"},
	}
}

func shellQuote(value string) string {
	result := "'"
	for _, character := range value {
		if character == '\'' {
			result += "'\\''"
		} else {
			result += string(character)
		}
	}
	return result + "'"
}
