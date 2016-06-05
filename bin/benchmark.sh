#!/bin/sh

NATIVE_BENCHMARK_DIR="/Users/aneeshneelam/benchmarks"
DIFUSE_BENCHMARK_DIR="/Users/aneeshneelam/Temp/Users/aneeshneelam/benchmarks"


for ((n=0;n<20;n++));
do
  echo "Native Write"
  time sh -c "dd if=/dev/zero of=${NATIVE_BENCHMARK_DIR}/testfile bs=100k count=1k && sync";
done

for ((n=0;n<20;n++));
do
  echo "Native Read"
  time sh -c "dd of=/dev/null if=${NATIVE_BENCHMARK_DIR}/testfile bs=100k count=1k && sync";
done

for ((n=0;n<20;n++));
do
  echo "DiFUSE Write"
  time sh -c "dd if=/dev/zero of=${DIFUSE_BENCHMARK_DIR}/testfile bs=100k count=1k && sync";
done

for ((n=0;n<20;n++));
do
  echo "DiFUSE Read"
  time sh -c "dd of=/dev/null if=${DIFUSE_BENCHMARK_DIR}/testfile bs=100k count=1k && sync";
done

rm ${NATIVE_BENCHMARK_DIR}/testfile


for ((n=0;n<10;n++));
do
echo "Native Bonnie++"
   bonnie++ -r 3072 -d ${NATIVE_BENCHMARK_DIR}
done

for ((n=0;n<10;n++));
do
echo "DiFUSE Bonnie++"
   bonnie++ -r 3072 -d ${DIFUSE_BENCHMARK_DIR}
done
