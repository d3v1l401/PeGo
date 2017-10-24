#!/bin/bash
disos=$(uname)
if [[ "$disos" == "Linux" ]]; then
    go build -buildmode=plugin "$(pwd)/plSources/GoLangIdentifier/main.go" -o "../../plugins/goident.p4pg"
else
    echo "Unsupported Go Build Architecture"
fi
