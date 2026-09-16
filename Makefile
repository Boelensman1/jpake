INSTALL_DEPS=node_modules
SRC_FILES=$(shell find src/)
TEST_FILES:=$(shell find tests/)

node_modules: package.json ./pnpm-lock.yaml
	pnpm install --frozen-lockfile || ( sleep 1; touch pnpm-lock.yaml; exit 1 ) # add the touch so if the install fails it will get rerun
	@if [ -e node_modules ]; then touch node_modules; fi

install: node_modules

clean:
	rm -rf node_modules coverage build

build: $(INSTALL_DEPS) $(SRC_FILES) tsconfig.json tsconfig.build.json
	pnpm exec tsc --project ./tsconfig.build.json
	@touch build

test: $(INSTALL_DEPS)
	pnpm exec vitest

coverage: $(INSTALL_DEPS) $(SRC_FILES) $(TEST_FILES)
	CI=1 pnpm exec vitest --coverage --coverage.exclude=build --coverage.exclude=tests --coverage.exclude=__mocks__

lint: $(INSTALL_DEPS)
	pnpm exec prettier --check .
	pnpm exec tsc --noEmit
	pnpm exec eslint

docs: $(INSTALL_DEPS) $(SRC_FILES) README.md
	pnpm exec typedoc src/main.mts

publish: build
	pnpm publish

.PHONY: clean lint test install
