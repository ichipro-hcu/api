FROM golang:1.23-alpine AS go
WORKDIR /
ADD go.mod go.sum main.go config.toml ./
RUN go mod download 
RUN go build main.go
CMD ["/main", "init-database-flag"]
