#!/bin/bash

ip addr | awk '/inet / && /192\.168\.22\.129/ {split($2, a, "/"); print a[1]}'
