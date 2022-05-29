FROM golang:1.18 AS build

WORKDIR /go/src/app

COPY . .

RUN go build -o launcher -ldflags "-s -w" .

FROM ghcr.io/graalvm/jdk:latest

WORKDIR /hath

COPY --from=build /go/src/app/launcher .

ENTRYPOINT ["/hath/launcher"]