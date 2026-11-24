.PHONY: test test-python test-go test-js test-dart test-cross vectors clean

test: test-python test-go test-js test-dart test-cross

test-python:
	cd python && python3 ecvrf.py

test-go:
	go test -v -count=1 ./...

test-js:
	cd js && node --test ecvrf.test.js

test-dart:
	cd dart && dart pub get && dart analyze --fatal-infos && dart test

test-cross:
	bash scripts/cross-validate.sh

vectors:
	cd python && python3 generate.py

clean:
	rm -rf scripts/.bin dart/.dart_tool
