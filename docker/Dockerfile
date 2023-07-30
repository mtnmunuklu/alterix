FROM golang:latest

WORKDIR /app
COPY . .

RUN go build -o alterix .

CMD ["./alterix"]