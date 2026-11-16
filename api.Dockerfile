FROM rust:alpine AS base
WORKDIR /core

FROM base AS builder

COPY . .

ENV RP_ID "vercel.click"
ENV RP_ORIGIN "https://vault.vercel.click"

RUN cargo build --release -p click-cloud


FROM base AS runner

COPY --from=builder /core/target/release/click-cloud ./click-cloud
EXPOSE 8080

CMD ["./click-cloud"]
