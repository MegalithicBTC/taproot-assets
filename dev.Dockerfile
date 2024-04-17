FROM golang:1.22.2 as builder

WORKDIR /app

COPY . /app

ENV CGO_ENABLED=0

RUN make install

# FINAL IMAGE
FROM alpine as final

COPY --from=builder /go/bin/tapd /bin/
COPY --from=builder /go/bin/tapcli /bin/

EXPOSE 10029
EXPOSE 8089

ENTRYPOINT ["tapd"]
