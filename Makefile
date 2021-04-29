setup-mac:
	brew install golangci-lint
	go install github.com/golang/mock/mockgen@v1.5.0
lint:
	golangci-lint run
test:
	go test -v ./pkg/... -cover
coverage:
	go test ./pkg/... -coverprofile=coverage.out
	go tool cover -func=coverage.out
deps:
	go mod tidy && go mod vendor

release:
	goreleaser --rm-dist

.PHONY: deps setup-mac release readme lint mocks
