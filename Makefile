.PHONY: test test-python test-go test-js test-ts test-dart test-c test-swift test-kotlin test-rust test-solana test-csharp test-haskell test-zig test-solidity test-cross vectors clean

test: test-python test-go test-js test-ts test-dart test-c test-swift test-kotlin test-rust test-solana test-csharp test-haskell test-zig test-solidity test-cross

test-python:
	cd python && python3 ecvrf.py

test-go:
	go test -v -count=1 ./...

test-js:
	cd js && node --test ecvrf.test.js

test-ts:
	cd typescript && ([ -d node_modules ] || ([ -f package-lock.json ] && npm ci || npm install)) && npm test

test-dart:
	cd dart && dart pub get && dart analyze --fatal-infos && dart test

test-c:
	cd c && make test

test-swift:
	cd swift && swift build && swift run ecvrf-test

test-kotlin:
	cd kotlin && ./gradlew test

test-rust:
	cd rust && cargo test

test-solana:
	cd solana && cargo test

test-csharp:
	cd csharp && dotnet test

test-haskell:
	cd haskell && cabal build all --enable-tests && cabal test --test-show-details=direct

test-zig:
	cd zig && zig build test

test-solidity:
	cd solidity && ([ -d lib/forge-std ] || forge install foundry-rs/forge-std --no-git) && forge test

test-cross:
	bash scripts/cross-validate.sh

vectors:
	cd python && python3 generate.py

clean:
	rm -rf scripts/.bin ecvrf-go dart/.dart_tool dart/ecvrf-dart
	rm -rf typescript/dist
	$(MAKE) -C c clean
	rm -rf swift/.build
	rm -rf kotlin/build kotlin/.gradle kotlin/.kotlin
	rm -rf rust/target solana/target
	rm -rf csharp/out csharp/Ecvrf/bin csharp/Ecvrf/obj csharp/Ecvrf.Cli/bin csharp/Ecvrf.Cli/obj csharp/Ecvrf.Tests/bin csharp/Ecvrf.Tests/obj
	rm -rf haskell/dist-newstyle
	rm -rf zig/.zig-cache zig/zig-out
	rm -rf solidity/out solidity/cache
