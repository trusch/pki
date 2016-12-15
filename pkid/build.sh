#!/bin/bash

go build -ldflags '-linkmode external -extldflags -static' || exit $?
docker build -t trusch/pkid . || exit $?

exit 0
