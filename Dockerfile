# docker run -d -p 3000:3000 -e RP_ORIGIN="http://localhost:3000" portfolio2

# docker run -d -p 3000:3000 -e SECRET_KEY="5nH/t4D22wUgzb5G71//1l3caclB0c41SYIfHfUeffECDIFNwZQMZeTzEHSGvxlNrp7n2oVaD5Y6v504NEIDBw==" -e RP_ORIGIN="http://localhost:3000" -v portfolio-data:/data --name portfolio-app portfolio2

FROM messense/rust-musl-cross:x86_64-musl AS builder

# Set environment variables for the build
ENV SQLX_OFFLINE=true
WORKDIR /portfolio

# Copy project files
COPY . .

# Build the project
# The vendored feature in openssl will compile OpenSSL from source and statically link it
# messense/rust-musl-cross already has all necessary build tools (perl, make, etc.)
RUN cargo build --release --target x86_64-unknown-linux-musl

# Strip the binary to reduce size (removes debug symbols)
RUN strip /portfolio/target/x86_64-unknown-linux-musl/release/portfolio

# Use scratch for minimal final image
FROM scratch

# Copy CA certificates for HTTPS support (needed if your app makes HTTPS requests)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary and required files
COPY --from=builder /portfolio/target/x86_64-unknown-linux-musl/release/portfolio /portfolio
COPY --from=builder /portfolio/migrations /migrations
COPY --from=builder /portfolio/templates /templates
COPY --from=builder /portfolio/static /static

EXPOSE 3000
ENTRYPOINT ["/portfolio"]