#!/bin/bash

dromajo_root=$(readlink -f $(dirname $0)/..)

echo "using dromajo_root:"$dromajo_root

pushd .
mkdir -p build_regression
cd build_regression

############################## DEBUG BUILD
pushd .
mkdir -p debug
cd debug
cmake -DCMAKE_BUILD_TYPE=Debug $dromajo_root

make -j
if [ $? -ne 0 ]; then
  echo "FIXME: debug build failed"
  exit 1
fi

make dromajo_cosim_test
if [ $? -ne 0 ]; then
  echo "FIXME: debug dromajo_cosim_test build failed"
  exit 1
fi

popd

############################## RELEASE BUILD
pushd .
mkdir -p release
cd release
cmake $dromajo_root

make -j
if [ $? -ne 0 ]; then
  echo "FIXME: release build failed"
  exit 1
fi

make dromajo_cosim_test
if [ $? -ne 0 ]; then
  echo "FIXME: release dromajo_cosim_test build failed"
  exit 1
fi

popd

############################## goldmem debug BUILD
pushd .
mkdir -p goldd
cd goldd
cmake -DCMAKE_BUILD_TYPE=Debug -DGOLDMEM=On $dromajo_root

make -j dromajo_cosim_test
if [ $? -ne 0 ]; then
  echo "FIXME: goldmem debug build failed"
  exit 1
fi

popd

############################## create trace

./release/dromajo --maxinsns 10k --trace 0 --ncpus 2 $dromajo_root/riscv-simple-tests/rv64ua-p-amoxor_d 2>check1.trace
if [ $? -ne 0 ]; then
  echo "FIXME: failed to create a release trace"
  exit 1
fi

./debug/dromajo --maxinsns 10k --trace 0 --ncpus 2 $dromajo_root/riscv-simple-tests/rv64ua-p-amoxor_d 2>check2.trace
if [ $? -ne 0 ]; then
  echo "FIXME: failed to create a debug trace"
  exit 1
fi

cmp check1.trace check2.trace
if [ $? -ne 0 ]; then
  echo "FIXME: debug and release trace do not match"
  exit 1
fi


############################## check trace

./release/dromajo_cosim_test  cosim check1.trace --ncpus 2 ../riscv-simple-tests/rv64ua-p-amoxor_d
if [ $? -ne 0 ]; then
  echo "FIXME: release check trace failed"
  exit 1
fi

./debug/dromajo_cosim_test  cosim check1.trace --ncpus 2 ../riscv-simple-tests/rv64ua-p-amoxor_d
if [ $? -ne 0 ]; then
  echo "FIXME: debug check trace failed"
  exit 1
fi

############################## check goldmem

./gold/dromajo_cosim_test  cosim check1.trace --ncpus 2 ../riscv-simple-tests/rv64ua-p-amoxor_d
if [ $? -ne 0 ]; then
  echo "FIXME: golemem debug check trace failed"
  exit 1
fi

echo "SUCCESS!!! the small regression passed!"

