# syntax=docker/dockerfile:1
FROM golang:1-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /local-acmpca

RUN mkdir /empty-dir

FROM gcr.io/distroless/static-debian12

WORKDIR /

COPY --from=build /empty-dir /db

COPY --from=build /local-acmpca /local-acmpca

ENV LOCAL_ACMPCA_ADDR=:8089
# make it live for the life of the container, or easier to volume up
ENV LOCAL_ACMPCA_STATE=/db/state.json

CMD ["/local-acmpca"]
