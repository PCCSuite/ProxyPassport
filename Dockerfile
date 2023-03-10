FROM golang:alpine AS build
RUN apk add git
ARG GOARCH=amd64
ENV GOARCH ${GOARCH}
ENV CGO_ENABLED 0
ADD . /go/src/ProxyPassport/
WORKDIR /go/src/ProxyPassport
RUN go build .

FROM alpine
COPY --from=build /go/src/ProxyPassport/ProxyPassport /bin/ProxyPassport
WORKDIR /data
CMD ProxyPassport