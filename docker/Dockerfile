# syntax=docker/dockerfile:1
# 黑潮 DNS 容器映像檔（說明：docs/docker.md）
#
# 映像檔裡不編譯：直接放 CI 編好、用 QEMU 實際執行測過的靜態執行檔（musl），跟 Release 的
# kuroshio-<target> 是同一個檔案。CI 先把各 CPU 的執行檔放到：
#   docker/bin/amd64/kuroshio   ← x86_64-unknown-linux-musl
#   docker/bin/arm64/kuroshio   ← aarch64-unknown-linux-musl
#   docker/bin/armv7/kuroshio   ← armv7-unknown-linux-musleabihf
# 建置內容是 repo 根目錄（docker/Dockerfile.dockerignore 只送需要的檔案進去）：
#   docker build -f docker/Dockerfile -t kuroshio-dns .

# 準備檔案用（只在建置的機器上跑，最後的映像檔裡沒有 alpine）
FROM --platform=$BUILDPLATFORM alpine:3.20 AS prep
ARG TARGETARCH
ARG TARGETVARIANT
COPY docker/bin/${TARGETARCH}${TARGETVARIANT}/kuroshio /out/usr/bin/kuroshio
# 唯讀資料（台灣 IP 清單、種子、評測名單、CDN 範圍、設定頁、公開頁）與預設自訂規則
COPY data /out/usr/share/kuroshio
COPY rules/default-custom-rules.txt /out/usr/share/kuroshio/
# 第一次啟動時 /config/config.json 不存在：從這裡複製一份（KUROSHIO_INIT_CONFIG）
COPY docker/config.json /out/usr/share/kuroshio/docker/config.json
COPY LICENSE /out/usr/share/doc/kuroshio/LICENSE
RUN chmod 755 /out/usr/bin/kuroshio \
 && mkdir -p /out/config /out/tmp \
 && chmod 1777 /out/tmp

FROM scratch
ARG VERSION=dev
COPY --from=prep /out/ /
# 時區：排程（每日評測、每月台灣 IP 清單…）與統計的日期在程式裡固定用台灣時間（UTC+8），
# 不看 TZ 也不需要時區資料；日誌的時間是 UTC（結尾的 Z）
ENV KUROSHIO_SHARE=/usr/share/kuroshio \
    KUROSHIO_INIT_CONFIG=/usr/share/kuroshio/docker/config.json
# 設定檔、admin.token、自訂規則、state/（快照）都在 /config：備份就是備份這個資料夾
VOLUME ["/config"]
WORKDIR /config
# 53 明文 DNS、853 DoT（TCP）/ DoQ（UDP）、443 DoH（TCP）/ DoH3（UDP）、8054 設定頁
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 443/tcp 443/udp 8054/tcp
STOPSIGNAL SIGTERM
# 0 = 明文 DNS 有在回答，1 = 沒有
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --start-interval=2s --retries=3 \
  CMD ["/usr/bin/kuroshio", "health", "-c", "/config/config.json"]
LABEL org.opencontainers.image.title="黑潮 DNS（Kuroshio DNS）" \
      org.opencontainers.image.description="台灣在地化的 DNS 伺服器：DoH / DoH3 / DoT / DoQ、過濾、CDN 台灣節點" \
      org.opencontainers.image.source="https://github.com/candy999/kuroshio-dns" \
      org.opencontainers.image.documentation="https://github.com/candy999/kuroshio-dns/blob/main/docs/docker.md" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}"
ENTRYPOINT ["/usr/bin/kuroshio", "run", "-c", "/config/config.json"]
