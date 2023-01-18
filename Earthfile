VERSION 0.6
FROM alpine

test:
    FROM opensuse/tumbleweed
    RUN zypper in -y go openssl-devel
    WORKDIR /build
    ENV GOPATH=/go
    # Cache layer for modules
    COPY go.mod go.sum ./
    RUN go mod download && go mod verify
    RUN go install -mod=mod github.com/onsi/ginkgo/v2/ginkgo
    COPY . .
    RUN PATH=$PATH:$GOPATH/bin ginkgo -v ./...
