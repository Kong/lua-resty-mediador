.PHONY: test lint

test:
	@busted -v -o gtest

lint:
	@luacheck lib --std luajit
