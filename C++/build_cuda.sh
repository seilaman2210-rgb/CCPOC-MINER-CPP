#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

NVCC="${NVCC:-nvcc}"
CXX="${CXX:-g++}"

echo "==> Compiling CUDA module with $NVCC"
$NVCC -O3 -std=c++17 -arch=all -c gpu_modules/nvidia_cuda.cu -o nvidia_cuda.o

echo "==> Linking plotter_cuda with $CXX"
$CXX -O3 -std=c++17 -pthread -o plotter_cuda plotter_cuda.cpp nvidia_cuda.o \
    -ljson-c -lcrypto -lcudart -lnvrtc -L"${CUDA_HOME:-/usr/local/cuda}/lib64" 2>/dev/null \
    || $CXX -O3 -std=c++17 -pthread -o plotter_cuda plotter_cuda.cpp nvidia_cuda.o \
       -ljson-c -lcrypto -lcudart

rm -f nvidia_cuda.o

echo
echo "Built ./plotter_cuda (run: ./plotter_cuda <wallet.json> ; kernel compiled into the binary)"
