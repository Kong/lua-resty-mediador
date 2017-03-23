.PHONY: test lint

test:
	@busted -v -o gtest

test-openresty:
	@./bin/busted -v -o gtest

lint:
	@luacheck lib --std luajit --read-globals ngx table.unpack
