VERSION := 1.0
EXTENSION_ID := cmgjlocmnppfpknaipdfodjhbplnhimk
PKG_IDENTIFIER := com.dragpass.keeper.pkg

MAC_BIN_AMD64 := dragpass-keeper-macos-x86_64
MAC_BIN_ARM64 := dragpass-keeper-macos-arm64
MAC_PKG_DIR := output/macos
MAC_PKG_AMD64 := $(MAC_PKG_DIR)/dragpass-keeper-macos-x86_64.pkg
MAC_PKG_ARM64 := $(MAC_PKG_DIR)/dragpass-keeper-macos-arm64.pkg

WIN_BIN := dragpass-keeper.exe
WIN_PKG_DIR := output/windows
WIN_PKG := $(WIN_PKG_DIR)/dragpass-keeper.exe
WIN_CC := x86_64-w64-mingw32-gcc # Windows cross-compiler for Go

LINUX_BIN_AMD64 := dragpass-keeper-linux-x86_64
LINUX_BIN_ARM64 := dragpass-keeper-linux-arm64
LINUX_PKG_DIR := output/linux
LINUX_DEB_AMD64 := $(LINUX_PKG_DIR)/dragpass-keeper-linux-x86_64.deb
LINUX_DEB_ARM64 := $(LINUX_PKG_DIR)/dragpass-keeper-linux-arm64.deb

MAC_SIG_AMD64 := $(MAC_PKG_AMD64).sig
MAC_SIG_ARM64 := $(MAC_PKG_ARM64).sig
WIN_SIG := $(WIN_PKG).sig
LINUX_SIG_AMD64 := $(LINUX_DEB_AMD64).sig
LINUX_SIG_ARM64 := $(LINUX_DEB_ARM64).sig

CHECKSUMS_FILE := output/checksums.txt

.PHONY: test test-verbose test-cover test-clipboard-e2e test-e2e-tag test-e2e-localtarget

# ── Tests ───────────────────────────────────────────
test:
	go test ./... -count=1

# The same suite with the keeper_e2e tag: the E2E-only code and its tests.
test-e2e-tag:
	go test -tags keeper_e2e ./... -count=1

# The suite with the test-only local credential target as well
# (internal/keystore/handlers/credential_localtarget_e2e.go).
test-e2e-localtarget:
	go test -tags "keeper_e2e keeper_e2e_localtarget" ./... -count=1

test-verbose:
	go test ./... -count=1 -v

test-cover:
	go test ./... -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out

test-clipboard-e2e:
	DRAGPASS_KEEPER_CLIPBOARD_E2E=1 go test ./internal/keystore/clipboard -count=1 -run ProductionSmoke -v

# ── MLS (Rust static library) ───────────────────────
# Release builds link the MLS library, so every build-* and pkg-* target below
# builds the staticlib for its own target first. MLS=0 gives the old
# library-free recipe for quick local work: on Linux that is also the static
# CGO_ENABLED=0 binary.
#
# Linking MLS turns cgo on everywhere. On Linux that makes the binary dynamic
# against glibc, which is why the release Linux binaries are built on the
# glibc baseline (scripts/linux-baseline-build.sh). It also compiles the real
# golang.design/x/clipboard instead of its nocgo stub. That needs the X11
# headers (libx11-dev) at build time, but the library is opened at runtime
# with dlopen and nothing links against libX11. The vendored copy is patched
# to try "libX11.so.6" (libx11-6) before "libX11.so" (libx11-dev only); see
# vendor/golang.design/x/clipboard/clipboard_linux.c.
#
# The cgo directives in internal/keystore/mls read the archive from
# mls/target/release on macOS and Linux, and from the gnu triple's directory on
# Windows. The per-target recipes below put the right archive in those places.
MLS ?= 1
MLS_DIR := mls
MLS_LIB := $(MLS_DIR)/target/release/libdragpass_mls.a
MLS_MAC_TRIPLES := aarch64-apple-darwin x86_64-apple-darwin

ifeq ($(MLS),1)
MLS_GO_TAGS := -tags mls
E2E_GO_TAGS := -tags "mls keeper_e2e"
E2E_LOCALTARGET_GO_TAGS := -tags "mls keeper_e2e keeper_e2e_localtarget"
HOST_MLS_LIB := $(if $(filter Darwin,$(shell uname -s)),mls-lib-macos,mls-lib)
LINUX_CGO := 1
MAC_MLS_LIB := mls-lib-macos
WIN_MLS_LIB := mls-lib-windows
LINUX_MLS_LIB := mls-lib
else
MLS_GO_TAGS :=
E2E_GO_TAGS := -tags keeper_e2e
E2E_LOCALTARGET_GO_TAGS := -tags "keeper_e2e keeper_e2e_localtarget"
HOST_MLS_LIB :=
LINUX_CGO := 0
MAC_MLS_LIB :=
WIN_MLS_LIB :=
LINUX_MLS_LIB :=
endif

.PHONY: mls-lib mls-lib-macos mls-lib-windows mls-test build-mls test-mls mls-clean

mls-lib:
	@echo "Building MLS static library..."
	@cd $(MLS_DIR) && cargo build --release --locked

# One universal archive at the path the darwin cgo directive reads. Each GOARCH
# link takes its own slice, and ld rejects an archive without a matching slice
# rather than linking the other arch, so the two binaries cannot swap
# libraries.
mls-lib-macos:
	@echo "Building MLS static library (universal: $(MLS_MAC_TRIPLES))..."
	@cd $(MLS_DIR) && cargo build --release --locked $(addprefix --target ,$(MLS_MAC_TRIPLES))
	@mkdir -p $(dir $(MLS_LIB))
	@lipo -create -output $(MLS_LIB) $(foreach t,$(MLS_MAC_TRIPLES),$(MLS_DIR)/target/$(t)/release/libdragpass_mls.a)

# Windows always links through mingw, so the archive has to be the gnu triple's
# even when cargo's host default would be MSVC.
mls-lib-windows:
	@echo "Building MLS static library (x86_64-pc-windows-gnu)..."
	@cd $(MLS_DIR) && cargo build --release --locked --target x86_64-pc-windows-gnu

mls-test:
	@cd $(MLS_DIR) && cargo test

build-mls: mls-lib
	@CGO_ENABLED=1 go build -tags mls ./...

test-mls: mls-lib
	@CGO_ENABLED=1 go test -tags mls ./... -count=1

mls-clean:
	@cd $(MLS_DIR) && cargo clean

# ── Build ───────────────────────────────────────────
.PHONY: all build pkg clean build-macos build-macos-amd64 build-macos-arm64 build-windows build-linux build-linux-amd64 build-linux-arm64 pkg-macos pkg-macos-amd64 pkg-macos-arm64 pkg-windows pkg-linux pkg-linux-amd64 pkg-linux-arm64 sign checksums release refresh uninstall

all: build pkg

build: build-macos build-windows build-linux
	@echo "All binaries built."

pkg: pkg-macos pkg-windows pkg-linux
	@echo "All installers packaged."

build-macos: build-macos-amd64 build-macos-arm64

build-macos-amd64: $(MAC_BIN_AMD64)
build-macos-arm64: $(MAC_BIN_ARM64)

# MAC_ARCH names the Go arch and build root, MAC_LABEL the user-facing arch.
# The macOS package targets below set the same values for their binaries.
$(MAC_BIN_AMD64) $(MAC_PKG_AMD64): MAC_ARCH := amd64
$(MAC_BIN_AMD64) $(MAC_PKG_AMD64): MAC_LABEL := x86_64
$(MAC_BIN_ARM64) $(MAC_PKG_ARM64): MAC_ARCH := arm64
$(MAC_BIN_ARM64) $(MAC_PKG_ARM64): MAC_LABEL := arm64

$(MAC_BIN_AMD64) $(MAC_BIN_ARM64): main.go go.mod $(MAC_MLS_LIB)
	@echo "Building macOS $(MAC_LABEL) binary: $@..."
	@CGO_ENABLED=1 GOOS=darwin GOARCH=$(MAC_ARCH) go build $(MLS_GO_TAGS) -o $@ .

# ── E2E builds ──────────────────────────────────────
# The browser E2E harness (dragpass tests/e2e-extension) needs the mock
# keyring, the keyring file mirror, and the test-only actions, which exist only
# with the keeper_e2e tag. These binaries have their own names so no package
# target can pick one up, and no release target sets the tag.
MAC_E2E_BIN_AMD64 := dragpass-keeper-e2e-macos-x86_64
MAC_E2E_BIN_ARM64 := dragpass-keeper-e2e-macos-arm64

.PHONY: build-e2e-macos-amd64 build-e2e-macos-arm64 build-e2e-localtarget check-release-no-e2e

build-e2e-macos-amd64: $(MAC_MLS_LIB)
	@echo "Building macOS x86_64 E2E binary: $(MAC_E2E_BIN_AMD64)..."
	@CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(E2E_GO_TAGS) -o $(MAC_E2E_BIN_AMD64) .

build-e2e-macos-arm64: $(MAC_MLS_LIB)
	@echo "Building macOS arm64 E2E binary: $(MAC_E2E_BIN_ARM64)..."
	@CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(E2E_GO_TAGS) -o $(MAC_E2E_BIN_ARM64) .

# An E2E binary for the host that can also send credential requests to a local
# HTTPS test server (loopback on KEEPER_E2E_LOCAL_TARGET_PORTS, TLS verified
# against KEEPER_E2E_LOCAL_TARGET_CA_FILE). For real-stack verification only;
# check-release-no-e2e rejects it.
E2E_LOCALTARGET_BIN := dragpass-keeper-e2e-localtarget
build-e2e-localtarget: $(HOST_MLS_LIB)
	@echo "Building E2E local-target binary: $(E2E_LOCALTARGET_BIN)..."
	@CGO_ENABLED=1 go build $(E2E_LOCALTARGET_GO_TAGS) -o $(E2E_LOCALTARGET_BIN) .

# Fails when BIN was built with the keeper_e2e tag or carries E2E-only code.
# The strings survive a stripped binary (-s -w), unlike symbols. Besides the
# E2E mode they cover the dev App origin opt-in and the root key override; a
# release build refuses those variables by prefix, so their full names never
# reach it.
E2E_ONLY_STRINGS := KEEPER_E2E_KEYRING_FILE KEEPER_E2E_OS_CLIPBOARD clipboard_get_last_hash \
	DRAGPASS_KEEPER_DEV_APP_ORIGIN KEEPER_ROOT_PUBLIC_KEY_BASE64 \
	KEEPER_E2E_LOCAL_TARGET_PORTS KEEPER_E2E_LOCAL_TARGET_CA_FILE

check-release-no-e2e:
	@test -n "$(BIN)" || { echo "usage: make check-release-no-e2e BIN=<binary>" >&2; exit 2; }
	@if go version -m "$(BIN)" | grep -q 'keeper_e2e'; then echo "$(BIN) was built with the keeper_e2e tag" >&2; exit 1; fi
	@for s in $(E2E_ONLY_STRINGS); do \
		if LC_ALL=C grep -aq "$$s" "$(BIN)"; then echo "$(BIN) carries E2E-only code ($$s)" >&2; exit 1; fi; \
	done
	@echo "$(BIN): no keeper_e2e tag and no E2E-only code"

build-windows: $(WIN_BIN)
$(WIN_BIN): main.go go.mod $(WIN_MLS_LIB)
	@echo "Building Windows binary: $(WIN_BIN)..."
	@CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=$(WIN_CC) go build $(MLS_GO_TAGS) -o $(WIN_BIN) .

build-linux: build-linux-amd64 build-linux-arm64

# On macOS, make build/pkg/release requires Docker for Linux builds. Each
# architecture uses the Ubuntu 20.04 release image and sets up its Go/Rust
# toolchains inside the container.
build-linux-amd64: $(LINUX_BIN_AMD64)
build-linux-arm64: $(LINUX_BIN_ARM64)

$(LINUX_BIN_AMD64): LINUX_ARCH := amd64
$(LINUX_BIN_ARM64): LINUX_ARCH := arm64

ifeq ($(shell uname -s),Darwin)
LINUX_BASELINE_IMAGE ?= ubuntu:20.04
LINUX_GO_VERSION ?= $(shell awk '$$1 == "toolchain" { toolchain = $$2 } $$1 == "go" { language = $$2 } END { version = toolchain; if (version == "" || version == "default") version = language; sub(/^go/, "", version); print version }' go.mod)
ifeq ($(strip $(LINUX_GO_VERSION)),)
$(error Could not determine Go version from go.mod)
endif

# macOS cannot supply the Linux C toolchain or glibc headers needed by the
# release cgo binaries. Build each architecture in its matching baseline image.
$(LINUX_BIN_AMD64) $(LINUX_BIN_ARM64): main.go go.mod
	@docker run --rm --platform linux/$(LINUX_ARCH) \
		-v "$$PWD:/work" -w /work \
		-e HOST_UID="$$(id -u)" -e HOST_GID="$$(id -g)" \
		-e GO_VERSION="$(LINUX_GO_VERSION)" \
		-e MLS="$(MLS)" \
		"$(LINUX_BASELINE_IMAGE)" \
		scripts/linux-baseline-build.sh "$(LINUX_ARCH)" "$(VERSION)"
.PHONY: $(LINUX_BIN_AMD64) $(LINUX_BIN_ARM64)
else
$(LINUX_BIN_AMD64) $(LINUX_BIN_ARM64): main.go go.mod $(LINUX_MLS_LIB)
	@echo "Building Linux $(LINUX_ARCH) binary: $@..."
	@CGO_ENABLED=$(LINUX_CGO) GOOS=linux GOARCH=$(LINUX_ARCH) go build $(MLS_GO_TAGS) -o $@ .
endif

pkg-macos: pkg-macos-amd64 pkg-macos-arm64

pkg-macos-amd64: $(MAC_PKG_AMD64)
pkg-macos-arm64: $(MAC_PKG_ARM64)

$(MAC_PKG_AMD64): $(MAC_BIN_AMD64)
$(MAC_PKG_ARM64): $(MAC_BIN_ARM64)
$(MAC_PKG_AMD64) $(MAC_PKG_ARM64): MAC_ROOT = build_root_macos_$(MAC_ARCH)
$(MAC_PKG_AMD64): MAC_BIN := $(MAC_BIN_AMD64)
$(MAC_PKG_ARM64): MAC_BIN := $(MAC_BIN_ARM64)

$(MAC_PKG_AMD64) $(MAC_PKG_ARM64):
	@echo "Creating macOS $(MAC_LABEL) package structure in ./$(MAC_ROOT)..."
	@rm -rf $(MAC_ROOT)
	@mkdir -p $(MAC_ROOT)/Library/Application\ Support/DragPass
	@mkdir -p $(MAC_ROOT)/Library/Application\ Support/Google/Chrome/NativeMessagingHosts
	@cp $(MAC_BIN) $(MAC_ROOT)/Library/Application\ Support/DragPass/dragpass-keeper
	@echo "{\n  \"name\": \"com.dragpass.keeper\",\n  \"description\": \"DragPass Device Key Storage\",\n  \"path\": \"/Library/Application Support/DragPass/dragpass-keeper\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": [\n    \"chrome-extension://$(EXTENSION_ID)/\"\n  ]\n}" > $(MAC_ROOT)/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.dragpass.keeper.json

	@echo "Creating output directory: $(MAC_PKG_DIR)..."
	@mkdir -p $(MAC_PKG_DIR)

	@echo "Building macOS $(MAC_LABEL) package: $@..."
	@pkgbuild --root ./$(MAC_ROOT) \
            --identifier $(PKG_IDENTIFIER) \
            --version $(VERSION) \
            $@
	@echo "Successfully built $@"

pkg-windows: $(WIN_PKG)
$(WIN_PKG): $(WIN_BIN) setup.iss
	@echo "Building Windows installer via Docker: $(WIN_PKG)..."
	@docker run --rm -v "$$PWD:/work" amake/innosetup "/DMyAppVersion=$(VERSION)" setup.iss
	@echo "Successfully built Windows installer."

pkg-linux: pkg-linux-amd64 pkg-linux-arm64

# The cgo binary needs glibc 2.31 or newer, the baseline it is built on, and
# libgcc_s for the Rust library's unwinder (panic = "unwind", see
# mls/Cargo.toml). Those are its NEEDED entries besides glibc's own.
#
# libX11 is deliberately not a dependency: the clipboard opens it with dlopen
# at runtime, so a machine without X11 (a server, a Wayland-only session) still
# installs and runs Keeper, and only decrypt-to-clipboard fails, explicitly.
DEB_DEPENDS := libc6 (>= 2.31), libgcc-s1

pkg-linux-amd64: $(LINUX_DEB_AMD64)
pkg-linux-arm64: $(LINUX_DEB_ARM64)

$(LINUX_DEB_AMD64): $(LINUX_BIN_AMD64)
$(LINUX_DEB_ARM64): $(LINUX_BIN_ARM64)
$(LINUX_DEB_AMD64): DEB_ARCH := amd64
$(LINUX_DEB_AMD64): DEB_BIN := $(LINUX_BIN_AMD64)
$(LINUX_DEB_ARM64): DEB_ARCH := arm64
$(LINUX_DEB_ARM64): DEB_BIN := $(LINUX_BIN_ARM64)
$(LINUX_DEB_AMD64) $(LINUX_DEB_ARM64): DEB_ROOT = build_root_linux_$(DEB_ARCH)

$(LINUX_DEB_AMD64) $(LINUX_DEB_ARM64):
	@echo "Creating Linux $(DEB_ARCH) package structure in ./$(DEB_ROOT)..."
	@rm -rf $(DEB_ROOT)
	@mkdir -p $(DEB_ROOT)/opt/dragpass
	@mkdir -p $(DEB_ROOT)/etc/opt/chrome/native-messaging-hosts
	@mkdir -p $(DEB_ROOT)/etc/chromium/native-messaging-hosts
	@cp $(DEB_BIN) $(DEB_ROOT)/opt/dragpass/dragpass-keeper
	@echo "{\n  \"name\": \"com.dragpass.keeper\",\n  \"description\": \"DragPass Device Key Storage\",\n  \"path\": \"/opt/dragpass/dragpass-keeper\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": [\n    \"chrome-extension://$(EXTENSION_ID)/\"\n  ]\n}" > $(DEB_ROOT)/etc/opt/chrome/native-messaging-hosts/com.dragpass.keeper.json
	@cp $(DEB_ROOT)/etc/opt/chrome/native-messaging-hosts/com.dragpass.keeper.json \
		$(DEB_ROOT)/etc/chromium/native-messaging-hosts/com.dragpass.keeper.json

	@echo "Creating output directory: $(LINUX_PKG_DIR)..."
	@mkdir -p $(LINUX_PKG_DIR)

	@echo "Building DEB $(DEB_ARCH) package via Docker: $@..."
	@mkdir -p $(DEB_ROOT)/DEBIAN
	@echo "Package: dragpass-keeper\nVersion: $(VERSION)\nSection: utils\nPriority: optional\nArchitecture: $(DEB_ARCH)\nDepends: $(DEB_DEPENDS)\nMaintainer: DragPass <vjinhyeokv@gmail.com>\nDescription: DragPass Device Key Storage\n Native messaging host for DragPass Chrome extension" > $(DEB_ROOT)/DEBIAN/control
	@docker run --rm -v "$$PWD:/work" -w /work debian:bookworm-slim sh -c "dpkg-deb --build $(DEB_ROOT) /work/$@"
	@echo "Successfully built $@"

sign:
	@echo "Signing release artifacts with GPG..."
	@if ! command -v gpg >/dev/null 2>&1; then \
		echo "Error: gpg is not installed. Please install GPG to sign releases."; \
		exit 1; \
	fi
	@echo "Signing macOS x86_64 package..."
	@gpg --detach-sign --output $(MAC_SIG_AMD64) $(MAC_PKG_AMD64)
	@echo "Signing macOS arm64 package..."
	@gpg --detach-sign --output $(MAC_SIG_ARM64) $(MAC_PKG_ARM64)
	@echo "Signing Windows installer..."
	@gpg --detach-sign --output $(WIN_SIG) $(WIN_PKG)
	@echo "Signing Linux x86_64 package..."
	@gpg --detach-sign --output $(LINUX_SIG_AMD64) $(LINUX_DEB_AMD64)
	@echo "Signing Linux arm64 package..."
	@gpg --detach-sign --output $(LINUX_SIG_ARM64) $(LINUX_DEB_ARM64)
	@echo "All artifacts signed successfully."

checksums:
	@echo "Generating SHA256 checksums..."
	@mkdir -p output
	@rm -f $(CHECKSUMS_FILE)
	@echo "# Hashes:" > $(CHECKSUMS_FILE)
	@echo "" >> $(CHECKSUMS_FILE)
	@echo "| Filename | SHA256 |" >> $(CHECKSUMS_FILE)
	@echo "|----------|--------|" >> $(CHECKSUMS_FILE)

	@for file in \
		$(MAC_BIN_AMD64) $(MAC_BIN_ARM64) \
		$(WIN_BIN) \
		$(LINUX_BIN_AMD64) $(LINUX_BIN_ARM64) \
		$(MAC_PKG_AMD64) $(MAC_SIG_AMD64) \
		$(MAC_PKG_ARM64) $(MAC_SIG_ARM64) \
		$(WIN_PKG) $(WIN_SIG) \
		$(LINUX_DEB_AMD64) $(LINUX_SIG_AMD64) \
		$(LINUX_DEB_ARM64) $(LINUX_SIG_ARM64); do \
		if [ -f "$$file" ]; then \
			filename=$$(basename "$$file"); \
			hash=$$(shasum -a 256 "$$file" | awk '{print $$1}'); \
			echo "| $$filename | $$hash |" >> $(CHECKSUMS_FILE); \
		fi \
	done

	@echo "" >> $(CHECKSUMS_FILE)
	@echo "Checksums written to $(CHECKSUMS_FILE)"
	@cat $(CHECKSUMS_FILE)

# ── Fast reinstall for development ──────────────────
# Build locally for the current platform → overwrite only the binary in the
# install location. Skips pkgbuild/installers, so it's much faster than
# rebuilding a .pkg. If Chrome already has a Native Messaging host process
# alive, disable + re-enable the extension so the new binary is loaded.
#
# ⚠️ refresh also wipes all Keeper entries from the OS Keychain (re-signup
#    required). Useful for resetting to a clean state when schema or encoding
#    changes during development. To preserve an enrolled state, replace the
#    binary manually instead of running refresh.
#
# `make refresh` only lists the Keychain items it would delete and exits.
# `make refresh CONFIRM=1` deletes them, then rebuilds and reinstalls.
MAC_INSTALL_PATH := /Library/Application Support/DragPass/dragpass-keeper
LINUX_INSTALL_PATH := /opt/dragpass/dragpass-keeper

# Keychain service and slot names used by Keeper: config/config.go, plus
# chat-runtime-epoch (internal/keystore/chat_runtime.go).
# config/makefile_slots_test.go fails when these drift from config.go.
KEEPER_KEYCHAIN_SERVICE := com.dragpass.keeper
KEEPER_KEYCHAIN_ACCOUNTS := \
	device_key device_id account_binding session_code \
	keeper_private_key keeper_public_key \
	pending_keeper_private_key pending_keeper_public_key \
	pending_recovery_keeper_private_key pending_recovery_keeper_public_key \
	pending_signup_prepare_input pending_signup_personal_device_wrapped_dek \
	personal_device_wrapped_dek pending_personal_key_bundle \
	server_public_key_active_version server_public_key_root_fingerprint \
	request_signing_private_key request_signing_public_key \
	pending_request_signing_private_key pending_request_signing_public_key \
	mls_leaf_signature_key mls_leaf_signature_key_pending \
	org_archive_private_key org_archive_public_key \
	org_archive_private_key_staging org_archive_public_key_staging \
	org_archive_session_private_key org_archive_session_public_key \
	account_archive_private_key account_archive_public_key \
	key-transparency-checkpoint-anchor peer-key-policy peer-key-owner \
	chat-runtime-epoch
# Slots whose names end in an id (server key version, org id, peer account,
# event digest, chat owner tag). Found by listing the Keychain.
KEEPER_KEYCHAIN_ACCOUNT_PREFIXES := \
	server_public_key_v \
	org_archive_private_key: org_archive_public_key: \
	org_archive_private_key_staging: org_archive_public_key_staging: \
	peer-pin: peer-pin-index: mls-leaf-newest: \
	key-transparency-known-event: key-transparency-pending-event: \
	chat-state-seal: chat-state-anchor:
SECURITY ?= security
KEYCHAIN_SLOTS = KEEPER_KEYCHAIN_SERVICE="$(KEEPER_KEYCHAIN_SERVICE)" \
	KEEPER_KEYCHAIN_ACCOUNTS="$(KEEPER_KEYCHAIN_ACCOUNTS)" \
	KEEPER_KEYCHAIN_ACCOUNT_PREFIXES="$(KEEPER_KEYCHAIN_ACCOUNT_PREFIXES)" \
	SECURITY="$(SECURITY)" sh scripts/keychain-slots.sh
# A recipe line that names $(MAKE) runs even under `make -n`, and refresh is
# one line, so `make -n refresh CONFIRM=1` used to purge the Keychain. Going
# through another variable keeps -n a dry run.
REFRESH_SUBMAKE = $(MAKE)

refresh:
	@OS=$$(uname -s); ARCH=$$(uname -m); \
	case "$$OS" in \
		Darwin) \
			case "$$ARCH" in \
				arm64) BIN=$(MAC_BIN_ARM64); TARGET=build-macos-arm64 ;; \
				x86_64) BIN=$(MAC_BIN_AMD64); TARGET=build-macos-amd64 ;; \
				*) echo "Unsupported macOS arch: $$ARCH"; exit 1 ;; \
			esac; \
			INSTALL_PATH="$(MAC_INSTALL_PATH)" ;; \
		Linux) \
			case "$$ARCH" in \
				x86_64) BIN=$(LINUX_BIN_AMD64); TARGET=build-linux-amd64 ;; \
				aarch64|arm64) BIN=$(LINUX_BIN_ARM64); TARGET=build-linux-arm64 ;; \
				*) echo "Unsupported Linux arch: $$ARCH"; exit 1 ;; \
			esac; \
			INSTALL_PATH="$(LINUX_INSTALL_PATH)" ;; \
		*) echo "Unsupported OS for refresh: $$OS (use make pkg-windows for Windows)"; exit 1 ;; \
	esac; \
	if [ "$(CONFIRM)" != "1" ]; then \
		echo "make refresh would delete the Keychain items below, rebuild $$BIN and install it to $$INSTALL_PATH."; \
		case "$$OS" in \
			Darwin) $(KEYCHAIN_SLOTS) list ;; \
			Linux) \
				echo "Secret Service items under service $(KEEPER_KEYCHAIN_SERVICE), cleared if present:"; \
				for acct in $(KEEPER_KEYCHAIN_ACCOUNTS); do echo "  will clear: $$acct"; done; \
				echo "  (slots named with an id are not cleared on Linux)" ;; \
		esac; \
		echo ""; \
		echo "Nothing was deleted. Run 'make refresh CONFIRM=1' to proceed."; \
		exit 0; \
	fi; \
	echo "Refreshing Keeper: $$OS/$$ARCH → $$INSTALL_PATH"; \
	echo "Purging Keychain entries (service=$(KEEPER_KEYCHAIN_SERVICE))..."; \
	case "$$OS" in \
		Darwin) $(KEYCHAIN_SLOTS) delete ;; \
		Linux) \
			if command -v secret-tool >/dev/null 2>&1; then \
				for acct in $(KEEPER_KEYCHAIN_ACCOUNTS); do \
					secret-tool clear service "$(KEEPER_KEYCHAIN_SERVICE)" account "$$acct" 2>/dev/null && echo "  cleared: $$acct" || echo "  (absent): $$acct"; \
				done; \
			else \
				echo "  ⚠️  secret-tool not installed — skipping Keychain purge (install libsecret-tools)"; \
			fi ;; \
	esac; \
	rm -f $$BIN; \
	$(REFRESH_SUBMAKE) $$TARGET; \
	if [ ! -f "$$BIN" ]; then echo "Build failed: $$BIN not found"; exit 1; fi; \
	echo "Installing (sudo required)..."; \
	sudo install -m 0755 $$BIN "$$INSTALL_PATH"; \
	echo "Refresh complete."; \
	echo ""; \
	echo "Next steps:"; \
	echo "  1. Disable/re-enable the DragPass Chrome extension to reload the Native Messaging host"; \
	echo "  2. (Optional) Reset the DragPass server DB if schema/encoding changed"; \
	echo "  3. (Optional) Reset Chrome Storage: uninstall + reinstall the extension, or log out / revoke device from the popup"; \
	echo "  4. Re-register account"

clean:
	@echo "Cleaning up build artifacts..."
	@rm -f $(MAC_BIN_AMD64) $(MAC_BIN_ARM64) $(WIN_BIN) $(LINUX_BIN_AMD64) $(LINUX_BIN_ARM64)
	@rm -rf build_root_macos_amd64 build_root_macos_arm64 build_root build_root_linux_amd64 build_root_linux_arm64 output

# ── Full uninstall ──────────────────────────────────
# zombie process kill → binary rm → Native Messaging manifest rm.
# A zombie keeper holding the persistent native messaging port keeps showing
# as "detected" in the popup/admin even after the binary/manifest are gone,
# so pkill runs first.
# Keychain entries are left alone — for a full reset, see the Keychain purge
# logic in the `refresh` target.
MAC_NM_MANIFEST := /Library/Application Support/Google/Chrome/NativeMessagingHosts/com.dragpass.keeper.json
LINUX_NM_MANIFEST_CHROME := /etc/opt/chrome/native-messaging-hosts/com.dragpass.keeper.json
LINUX_NM_MANIFEST_CHROMIUM := /etc/chromium/native-messaging-hosts/com.dragpass.keeper.json

uninstall:
	@echo "Killing running keeper processes..."; \
	if pkill -f dragpass-keeper 2>/dev/null; then \
		echo "  killed"; \
	else \
		echo "  (none running)"; \
	fi; \
	rm_path() { \
		if [ -f "$$1" ]; then \
			sudo rm -f "$$1" && echo "  deleted: $$1"; \
		else \
			echo "  (absent): $$1"; \
		fi; \
	}; \
	OS=$$(uname -s); \
	case "$$OS" in \
		Darwin) \
			echo "Removing binary..."; \
			rm_path "$(MAC_INSTALL_PATH)"; \
			echo "Removing Native Messaging manifest..."; \
			rm_path "$(MAC_NM_MANIFEST)" ;; \
		Linux) \
			echo "Removing binary..."; \
			rm_path "$(LINUX_INSTALL_PATH)"; \
			echo "Removing Native Messaging manifests..."; \
			rm_path "$(LINUX_NM_MANIFEST_CHROME)"; \
			rm_path "$(LINUX_NM_MANIFEST_CHROMIUM)" ;; \
		*) echo "Unsupported OS for uninstall: $$OS (Windows: use unins000.exe)"; exit 1 ;; \
	esac; \
	echo "Uninstall complete."; \
	echo ""; \
	echo "Next steps:"; \
	echo "  1. Disable/re-enable the DragPass Chrome extension to drop the native-messaging port"; \
	echo "  2. (Optional) Purge Keychain — see refresh target if you want a clean re-register"

release: pkg sign checksums
ifndef TAG
	$(error TAG is not set. Usage: make release TAG=v1.0.0)
endif
	@echo "Creating git tag $(TAG)..."
	@git tag $(TAG)
	@git push origin $(TAG)

	@echo "Preparing release notes with checksums and changelog..."
	@PREV_TAG=$$(git describe --tags --abbrev=0 $(TAG)^ 2>/dev/null || echo ""); \
	if [ -z "$$PREV_TAG" ]; then \
		git log --pretty=format:"%h - %s" $(TAG) > /tmp/release_changes.txt; \
	else \
		git log --pretty=format:"%h - %s" $$PREV_TAG..$(TAG) > /tmp/release_changes.txt; \
	fi; \
	echo "# Changes:" > /tmp/release_notes.txt; \
	cat /tmp/release_changes.txt >> /tmp/release_notes.txt; \
	echo "" >> /tmp/release_notes.txt; \
	cat $(CHECKSUMS_FILE) >> /tmp/release_notes.txt; \
	echo "Uploading artifacts to GitHub Release..."; \
	gh release create $(TAG) \
	--title "Release version: $(TAG)" \
	--notes-file /tmp/release_notes.txt \
	$(MAC_PKG_AMD64) $(MAC_SIG_AMD64) \
	$(MAC_PKG_ARM64) $(MAC_SIG_ARM64) \
	$(WIN_PKG) $(WIN_SIG) \
	$(LINUX_DEB_AMD64) $(LINUX_SIG_AMD64) \
	$(LINUX_DEB_ARM64) $(LINUX_SIG_ARM64) \
	$(CHECKSUMS_FILE); \
	rm -f /tmp/release_notes.txt /tmp/release_changes.txt

	@echo "Release $(TAG) created successfully."
