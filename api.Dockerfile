FROM rust:alpine AS base
WORKDIR /core

FROM base AS builder

COPY . .

ENV CLOUD_RP_ID = "cloud.secretpass.cloud"
ENV CLOUD_RP_ORIGIN = "https://cloud.secretpass.cloud"
ENV LOCAL_RP_ID = "local.secretpass.cloud"
ENV LOCAL_RP_ORIGIN = "https://local.secretpass.cloud"

RUN cargo build -p secretpass-cloud


FROM base AS runner

COPY --from=builder /core/target/release/secretpass-cloud ./secretpass-cloud
EXPOSE 8080

CMD ["./secretpass-cloud"]
