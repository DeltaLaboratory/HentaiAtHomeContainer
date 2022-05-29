FROM golang:1.18 AS build

WORKDIR /go/src/app

COPY . .

RUN go build -o launcher -ldflags "-s -w" .

FROM ghcr.io/graalvm/jdk:latest

WORKDIR /hath

RUN mkdir "/manager"

COPY --from=build /go/src/app/launcher /manager

ENTRYPOINT ["/manager/launcher"]