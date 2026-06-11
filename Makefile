APP ?= openagent
XDG_CONFIG_HOME ?= $(HOME)/.config
GLOBAL_CONFIG_DIR ?= $(XDG_CONFIG_HOME)/$(APP)
LOCAL_OPENAGENT_DIR := .openagent
DEPLOY_DIRS := agent skills tool ctf docs

.PHONY: deploy help install-tools build run dev clean clean-build typecheck

deploy:
	@test -d "$(LOCAL_OPENAGENT_DIR)" || { echo "missing $(LOCAL_OPENAGENT_DIR)"; exit 1; }
	@mkdir -p "$(GLOBAL_CONFIG_DIR)"
	@for dir in $(DEPLOY_DIRS); do \
		if [ -d "$(LOCAL_OPENAGENT_DIR)/$$dir" ]; then \
			rm -rf "$(GLOBAL_CONFIG_DIR)/$$dir"; \
			cp -a "$(LOCAL_OPENAGENT_DIR)/$$dir" "$(GLOBAL_CONFIG_DIR)/$$dir"; \
			echo "deployed $$dir -> $(GLOBAL_CONFIG_DIR)/$$dir"; \
		fi; \
	done
	@node -e 'const fs=require("fs"); const p="$(GLOBAL_CONFIG_DIR)/openagent.jsonc"; const cfg=fs.existsSync(p)?JSON.parse(fs.readFileSync(p,"utf8")):{"$$schema":"https://openagent.ai/config.json"}; cfg.permission??={}; cfg.permission.external_directory??={}; cfg.permission.external_directory["~/.config/$(APP)/docs/*"]="allow"; fs.writeFileSync(p, JSON.stringify(cfg,null,2)+"\n");'
	@echo "allowed docs external_directory -> ~/.config/$(APP)/docs/*"
	@echo "global $(APP) config dir: $(GLOBAL_CONFIG_DIR)"

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "  deploy     Deploy local .openagent CTF files and docs to global config (default)"
	@echo "  install-tools Install local development and CTF environment tools"
	@echo "  build      Build the openagent binary (linux-x64)"
	@echo "  run        Run the built binary"
	@echo "  dev        Run in dev mode (bun src/index.ts)"
	@echo "  clean      Remove deployed global .openagent CTF files and docs"
	@echo "  clean-build Remove build artifacts and caches"
	@echo "  typecheck  Type-check all packages"
	@echo ""
	@echo "Variables:"
	@echo "  APP=$(APP)"
	@echo "  GLOBAL_CONFIG_DIR=$(GLOBAL_CONFIG_DIR)"

install-tools:
	bash scripts/install-env.sh

build:
	bun run --cwd packages/openagent script/build.ts --single --skip-install

run:
	./packages/openagent/dist/openagent-linux-x64/bin/openagent

dev:
	bun run --cwd packages/openagent --conditions=browser src/index.ts

clean:
	@for dir in $(DEPLOY_DIRS); do \
		rm -rf "$(GLOBAL_CONFIG_DIR)/$$dir"; \
		echo "removed $(GLOBAL_CONFIG_DIR)/$$dir"; \
	done
	@rmdir "$(GLOBAL_CONFIG_DIR)" 2>/dev/null || true
	@echo "cleaned global $(APP) deployment"

clean-build:
	rm -rf packages/openagent/dist
	rm -rf packages/*/.turbo
	rm -rf packages/*/ts-dist
	rm -rf .turbo
	find packages -name "*.bun-build" -delete
	find packages -name "tsconfig.tsbuildinfo" -delete

typecheck:
	bun turbo typecheck
