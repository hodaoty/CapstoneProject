#!/bin/bash
set -e
echo "Syncing CapstoneProject from leader..."
git fetch origin
BRANCH=$(git symbolic-ref --short HEAD)
git reset --hard origin/$BRANCH
git clean -fd --exclude=sync_from_leader.sh
echo "Syncing ML model..."
cd ml_model/API-Threat-Detection-Model
git pull origin main
cd ../..
echo "Done. Both repos are up to date."
