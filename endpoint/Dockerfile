FROM rust:1.73 as builder
WORKDIR /app
COPY . .
RUN cargo build --release


FROM debian:bookworm-slim as runner

RUN useradd -ms /bin/bash app

USER app
WORKDIR /app

COPY --from=builder /app/target/release/bootstrap /app/pathfinder-api

ENV ROCKET_ADDRESS=0.0.0.0
ENV ROCKET_SECRET_KEY=
ENV ROCKET_PORT=8000

EXPOSE 8000

CMD ["./pathfinder-api"]
