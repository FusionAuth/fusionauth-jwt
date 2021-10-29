#!/usr/bin/env bash

cd $1

echo "stash it"
git stash

echo "branch it"
git checkout -b moreDerEncoding

echo "pop it"
git stash pop

echo "add it"
git add .

echo "commit it"
git commit -m "working"

echo "set upstream"
git push --set-upstream origin moreDerEncoding

echo ""
