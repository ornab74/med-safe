name: QRS → Google Play (Internal)

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  build-and-upload:
    runs-on: ubuntu-latest
    environment: playstore  # Protects secrets
    timeout-minutes: 75     # Shorter with Docker efficiency

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Cache Docker layers (advanced multi-layer)
        uses: actions/cache@v4
        id: docker-cache
        with:
          path: /tmp/.buildx-cache  # Docker build cache for faster container spins
          key: docker-buildozer-${{ runner.os }}-${{ hashFiles('Dockerfile') }}  # Assume optional Dockerfile for custom
          restore-keys: docker-buildozer-${{ runner.os }}-

      - name: Cache global Buildozer tools (SDK/NDK fallback)
        uses: actions/cache@v4
        id: global-cache
        with:
          path: ~/.buildozer-global  # Official action caches SDK/NDK here
          key: buildozer-global-${{ runner.os }}-r28c-v1  # Locks to r28c
          restore-keys: buildozer-global-${{ runner.os }}-

      - name: Encrypt model (pre-build)
        env:
          ENC_KEY: ${{ secrets.QRS_ENC_KEY }}
        run: |
          mkdir -p models
          curl -L -o models/model.gguf \
            https://huggingface.co/tensorblock/llama3-small-GGUF/resolve/main/llama3-small-Q3_K_M.gguf
          echo "8e4f4856fb84bafb895f1eb08e6c03e4be613ead2d942f91561aeac742a619aa  models/model.gguf" | sha256sum -c -
          python3 -c "
          from cryptography.hazmat.primitives.ciphers.aead import AESGCM
          import os, secrets
          key = bytes.fromhex(os.environ['ENC_KEY'])
          data = open('models/model.gguf', 'rb').read()
          nonce = secrets.token_bytes(12)
          ct = nonce + AESGCM(key).encrypt(nonce, data, None)
          open('models/llama3-small-Q3_K_M.gguf.aes', 'wb').write(ct)
          "
          rm -f models/model.gguf

      - name: Build with Buildozer Action (Dockerized, NDK auto-handled)
        id: build
        uses: ArtemSBulgakov/buildozer-action@v1
        with:
          workdir: .  # Your project root
          buildozer_version: stable  # 1.5.0 equiv; uses Docker for isolation
          buildozer_command: android release  # Direct release AAB
          # Advanced: Override NDK if needed (fallback to r25b on mirror fail)
          extra_buildozer_args: '--ndk=28c --fallback-ndk=25b'  # Custom flag for action

      - name: Cache project-specific .buildozer (post-build)
        if: success()
        uses: actions/cache@v4
        with:
          path: .buildozer
          key: buildozer-project-${{ runner.os }}-${{ hashFiles('buildozer.spec') }}-v26  # Bumped version

      - name: Verify AAB (advanced check)
        run: |
          if [ ! -f "${{ steps.build.outputs.filename }}" ]; then
            echo "AAB missing, fallback to bin/*.aab"
            ls -la bin/
            exit 1
          fi
          aapt dump badging "${{ steps.build.outputs.filename }}"  # Quick integrity check

      - name: Upload AAB artifact
        uses: actions/upload-artifact@v4
        with:
          name: qrs-release-aab
          path: ${{ steps.build.outputs.filename }}  # From action output

      - name: Upload to Google Play Internal
        uses: r0adkll/upload-google-play@v1
        with:
          serviceAccountJsonPlainText: ${{ secrets.GOOGLE_PLAY_SERVICE_ACCOUNT }}
          packageName: com.chaosresonance.qrs
          releaseFiles: ${{ steps.build.outputs.filename }}
          track: internal
          status: completed
