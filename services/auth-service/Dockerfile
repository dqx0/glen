# Multi-stage build
FROM golang:1.24.4-alpine AS builder

# 作業ディレクトリを設定
WORKDIR /app

# 依存関係ファイルをコピー
COPY go.mod go.sum ./

# 依存関係をダウンロード
RUN go mod download

# ソースコードをコピー
COPY . .

# アプリケーションをビルド
RUN CGO_ENABLED=0 GOOS=linux go build -o auth-service ./cmd/server

# 本番用イメージ
FROM alpine:3.19

# セキュリティアップデートとCA証明書をインストール
RUN apk --no-cache add ca-certificates

# 作業ディレクトリを設定
WORKDIR /root/

# ビルドされたバイナリをコピー
COPY --from=builder /app/auth-service .

# ポートを公開
EXPOSE 8081

# ヘルスチェック
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8081/health || exit 1

# アプリケーションを実行
CMD ["./auth-service"]