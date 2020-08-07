#!/bin/bash
protoc -I=./thirdparty/proto/tron -I/usr/local/include -I./thirdparty/proto/googleapis --go_out=plugins=grpc,paths=source_relative:./proto ./thirdparty/proto/tron/core/*.proto ./thirdparty/proto/tron/core/contract/*.proto 
protoc -I=./thirdparty/proto/tron -I/usr/local/include -I./thirdparty/proto/googleapis --go_out=plugins=grpc,paths=source_relative:./proto ./thirdparty/proto/tron/api/*.proto
