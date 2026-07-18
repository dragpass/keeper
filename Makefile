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

.PHONY: test test-verbose test-cover test-clipboard-e2e

# ── Tests ───────────────────────────────────────────
test:
	go test ./... -count=1

test-verbose:
	go test ./... -count=1 -v

test-cover:
	go test ./... -count=1 -coverprofile=coverage.out
	go tool cover -func=coverage.out

test-clipboard-e2e:
	DRAGPASS_KEEPER_CLIPBOARD_E2E=1 go test ./internal/keystore/clipboard -count=1 -run ProductionSmoke -v

# ── Build ───────────────────────────────────────────
.PHONY: all build pkg clean build-macos build-macos-amd64 build-macos-arm64 build-windows build-linux build-linux-amd64 build-linux-arm64 pkg-macos pkg-macos-amd64 pkg-macos-arm64 pkg-windows pkg-linux pkg-linux-amd64 pkg-linux-arm64 sign checksums release refresh uninstall

all: build pkg

build: build-macos build-windows build-linux
	@echo "All binaries built."

pkg: pkg-macos pkg-windows pkg-linux
	@echo "All installers packaged."

build-macos: build-macos-amd64 build-macos-arm64

build-macos-amd64: $(MAC_BIN_AMD64)
$(MAC_BIN_AMD64): main.go go.mod
	@echo "Building macOS x86_64 binary: $(MAC_BIN_AMD64)..."
	@CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o $(MAC_BIN_AMD64) .

build-macos-arm64: $(MAC_BIN_ARM64)
$(MAC_BIN_ARM64): main.go go.mod
	@echo "Building macOS arm64 binary: $(MAC_BIN_ARM64)..."
	@CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o $(MAC_BIN_ARM64) .

build-windows: $(WIN_BIN)
$(WIN_BIN): main.go go.mod
	@echo "Building Windows binary: $(WIN_BIN)..."
	@CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=$(WIN_CC) go build -o $(WIN_BIN) .

build-linux: build-linux-amd64 build-linux-arm64

build-linux-amd64: $(LINUX_BIN_AMD64)
$(LINUX_BIN_AMD64): main.go go.mod
	@echo "Building Linux amd64 binary: $(LINUX_BIN_AMD64)..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(LINUX_BIN_AMD64) .

build-linux-arm64: $(LINUX_BIN_ARM64)
$(LINUX_BIN_ARM64): main.go go.mod
	@echo "Building Linux arm64 binary: $(LINUX_BIN_ARM64)..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(LINUX_BIN_ARM64) .

pkg-macos: pkg-macos-amd64 pkg-macos-arm64

pkg-macos-amd64: $(MAC_PKG_AMD64)
$(MAC_PKG_AMD64): $(MAC_BIN_AMD64)
	@echo "Creating macOS x86_64 package structure in ./build_root_macos_amd64..."
	@rm -rf build_root_macos_amd64
	@mkdir -p build_root_macos_amd64/Library/Application\ Support/DragPass
	@mkdir -p build_root_macos_amd64/Library/Application\ Support/Google/Chrome/NativeMessagingHosts
	@cp $(MAC_BIN_AMD64) build_root_macos_amd64/Library/Application\ Support/DragPass/dragpass-keeper
	@echo "{\n  \"name\": \"com.dragpass.keeper\",\n  \"description\": \"DragPass Device Key Storage\",\n  \"path\": \"/Library/Application Support/DragPass/dragpass-keeper\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": [\n    \"chrome-extension://$(EXTENSION_ID)/\"\n  ]\n}" > build_root_macos_amd64/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.dragpass.keeper.json

	@echo "Creating output directory: $(MAC_PKG_DIR)..."
	@mkdir -p $(MAC_PKG_DIR)

	@echo "Building macOS x86_64 package: $(MAC_PKG_AMD64)..."
	@pkgbuild --root ./build_root_macos_amd64 \
            --identifier $(PKG_IDENTIFIER) \
            --version $(VERSION) \
            $(MAC_PKG_AMD64)
	@echo "Successfully built $(MAC_PKG_AMD64)"

pkg-macos-arm64: $(MAC_PKG_ARM64)
$(MAC_PKG_ARM64): $(MAC_BIN_ARM64)
	@echo "Creating macOS arm64 package structure in ./build_root_macos_arm64..."
	@rm -rf build_root_macos_arm64
	@mkdir -p build_root_macos_arm64/Library/Application\ Support/DragPass
	@mkdir -p build_root_macos_arm64/Library/Application\ Support/Google/Chrome/NativeMessagingHosts
	@cp $(MAC_BIN_ARM64) build_root_macos_arm64/Library/Application\ Support/DragPass/dragpass-keeper
	@echo "{\n  \"name\": \"com.dragpass.keeper\",\n  \"description\": \"DragPass Device Key Storage\",\n  \"path\": \"/Library/Application Support/DragPass/dragpass-keeper\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": [\n    \"chrome-extension://$(EXTENSION_ID)/\"\n  ]\n}" > build_root_macos_arm64/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.dragpass.keeper.json

	@echo "Creating output directory: $(MAC_PKG_DIR)..."
	@mkdir -p $(MAC_PKG_DIR)

	@echo "Building macOS arm64 package: $(MAC_PKG_ARM64)..."
	@pkgbuild --root ./build_root_macos_arm64 \
            --identifier $(PKG_IDENTIFIER) \
            --version $(VERSION) \
            $(MAC_PKG_ARM64)
	@echo "Successfully built $(MAC_PKG_ARM64)"

pkg-windows: $(WIN_PKG)
$(WIN_PKG): $(WIN_BIN) setup.iss
	@echo "Building Windows installer via Docker: $(WIN_PKG)..."
	@docker run --rm -v "$$PWD:/work" amake/innosetup setup.iss
	@echo "Successfully built Windows installer."

pkg-linux: pkg-linux-amd64 pkg-linux-arm64

pkg-linux-amd64: $(LINUX_DEB_AMD64)
$(LINUX_DEB_AMD64): $(LINUX_BIN_AMD64)
	@echo "Creating Linux amd64 package structure in ./build_root_linux_amd64..."
	@rm -rf build_root_linux_amd64
	@mkdir -p build_root_linux_amd64/opt/dragpass
	@mkdir -p build_root_linux_amd64/etc/opt/chrome/native-messaging-hosts
	@mkdir -p build_root_linux_amd64/etc/chromium/native-messaging-hosts
	@cp $(LINUX_BIN_AMD64) build_root_linux_amd64/opt/dragpass/dragpass-keeper
	@echo "{\n  \"name\": \"com.dragpass.keeper\",\n  \"description\": \"DragPass Device Key Storage\",\n  \"path\": \"/opt/dragpass/dragpass-keeper\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": [\n    \"chrome-extension://$(EXTENSION_ID)/\"\n  ]\n}" > build_root_linux_amd64/etc/opt/chrome/native-messaging-hosts/com.dragpass.keeper.json
	@cp build_root_linux_amd64/etc/opt/chrome/native-messaging-hosts/com.dragpass.keeper.json \
		build_root_linux_amd64/etc/chromium/native-messaging-hosts/com.dragpass.keeper.json

	@echo "Creating output directory: $(LINUX_PKG_DIR)..."
	@mkdir -p $(LINUX_PKG_DIR)

	@echo "Building DEB amd64 package via Docker: $(LINUX_DEB_AMD64)..."
	@mkdir -p build_root_linux_amd64/DEBIAN
	@echo "Package: dragpass-keeper\nVersion: $(VERSION)\nSection: utils\nPriority: optional\nArchitecture: amd64\nMaintainer: DragPass <vjinhyeokv@gmail.com>\nDescription: DragPass Device Key Storage\n Native messaging host for DragPass Chrome extension" > build_root_linux_amd64/DEBIAN/control
	@docker run --rm -v "$$PWD:/work" -w /work debian:bookworm-slim sh -c "dpkg-deb --build build_root_linux_amd64 /work/$(LINUX_DEB_AMD64)"
	@echo "Successfully built $(LINUX_DEB_AMD64)"

pkg-linux-arm64: $(LINUX_DEB_ARM64)
$(LINUX_DEB_ARM64): $(LINUX_BIN_ARM64)
	@echo "Creating Linux arm64 package structure in ./build_root_linux_arm64..."
	@rm -rf build_root_linux_arm64
	@mkdir -p build_root_linux_arm64/opt/dragpass
	@mkdir -p build_root_linux_arm64/etc/opt/chrome/native-messaging-hosts
	@mkdir -p build_root_linux_arm64/etc/chromium/native-messaging-hosts
	@cp $(LINUX_BIN_ARM64) build_root_linux_arm64/opt/dragpass/dragpass-keeper
	@echo "{\n  \"name\": \"com.dragpass.keeper\",\n  \"description\": \"DragPass Device Key Storage\",\n  \"path\": \"/opt/dragpass/dragpass-keeper\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": [\n    \"chrome-extension://$(EXTENSION_ID)/\"\n  ]\n}" > build_root_linux_arm64/etc/opt/chrome/native-messaging-hosts/com.dragpass.keeper.json
	@cp build_root_linux_arm64/etc/opt/chrome/native-messaging-hosts/com.dragpass.keeper.json \
		build_root_linux_arm64/etc/chromium/native-messaging-hosts/com.dragpass.keeper.json

	@echo "Creating output directory: $(LINUX_PKG_DIR)..."
	@mkdir -p $(LINUX_PKG_DIR)

	@echo "Building DEB arm64 package via Docker: $(LINUX_DEB_ARM64)..."
	@mkdir -p build_root_linux_arm64/DEBIAN
	@echo "Package: dragpass-keeper\nVersion: $(VERSION)\nSection: utils\nPriority: optional\nArchitecture: arm64\nMaintainer: DragPass <vjinhyeokv@gmail.com>\nDescription: DragPass Device Key Storage\n Native messaging host for DragPass Chrome extension" > build_root_linux_arm64/DEBIAN/control
	@docker run --rm -v "$$PWD:/work" -w /work debian:bookworm-slim sh -c "dpkg-deb --build build_root_linux_arm64 /work/$(LINUX_DEB_ARM64)"
	@echo "Successfully built $(LINUX_DEB_ARM64)"

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
MAC_INSTALL_PATH := /Library/Application Support/DragPass/dragpass-keeper
LINUX_INSTALL_PATH := /opt/dragpass/dragpass-keeper

# Keychain Service name and account list used by Keeper.
# (Keep in sync with dragpass-keeper/config/config.go.)
KEEPER_KEYCHAIN_SERVICE := com.dragpass.keeper
KEEPER_KEYCHAIN_ACCOUNTS := device_key keeper_private_key keeper_public_key server_public_key session_code pending_keeper_private_key pending_keeper_public_key

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
	echo "Refreshing Keeper: $$OS/$$ARCH → $$INSTALL_PATH"; \
	echo "Purging Keychain entries (service=$(KEEPER_KEYCHAIN_SERVICE))..."; \
	case "$$OS" in \
		Darwin) \
			for acct in $(KEEPER_KEYCHAIN_ACCOUNTS); do \
				security delete-generic-password -s "$(KEEPER_KEYCHAIN_SERVICE)" -a "$$acct" >/dev/null 2>&1 && echo "  deleted: $$acct" || echo "  (absent): $$acct"; \
			done ;; \
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
	$(MAKE) $$TARGET; \
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
