.PHONY: help build run dev clean typecheck

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "  build      Build the openagent binary (linux-x64)"
	@echo "  run        Run the built binary"
	@echo "  dev        Run in dev mode (bun src/index.ts)"
	@echo "  clean      Remove build artifacts and caches"
	@echo "  typecheck  Type-check all packages"

build:
	bun run --cwd packages/openagent script/build.ts --single --skip-install

run:
	./packages/openagent/dist/openagent-linux-x64/bin/openagent

dev:
	bun run --cwd packages/openagent --conditions=browser src/index.ts

clean:
	rm -rf packages/openagent/dist
	rm -rf packages/*/.turbo
	rm -rf packages/*/ts-dist
	rm -rf .turbo
	find packages -name "*.bun-build" -delete
	find packages -name "tsconfig.tsbuildinfo" -delete

typecheck:
	bun turbo typecheck
