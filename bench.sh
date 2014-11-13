#!/bin/sh

function error {
  echo "$@"
  exit 1
}

here=${PWD}
echo "pwd: ${here}"

fmt="%U %S %M"
echo "# user sys maxrss" > ${here}/psiphi-raw.bench
echo "# user sys maxrss" > ${here}/psiphi-null.bench
echo "# user sys maxrss" > ${here}/psiphi-mt.bench
echo "# user sys maxrss" > ${here}/psiphi-v2d.bench
echo "# user sys maxrss" > ${here}/relax-raw.bench
echo "# user sys maxrss" > ${here}/relax-null.bench
echo "# user sys maxrss" > ${here}/relax-mt.bench
echo "# user sys maxrss" > ${here}/relax-v2d.bench
echo "# user sys maxrss" > ${here}/linpack-raw.bench
echo "# user sys maxrss" > ${here}/linpack-null.bench
echo "# user sys maxrss" > ${here}/linpack-mt.bench
echo "# user sys maxrss" > ${here}/linpack-v2d.bench
echo "# user sys maxrss" > ${here}/nallocs-raw.bench
echo "# user sys maxrss" > ${here}/nallocs-null.bench
echo "# user sys maxrss" > ${here}/nallocs-mt.bench
echo "# user sys maxrss" > ${here}/nallocs-v2d.bench
for i in 0 1 2 3 4 5 6 7 8; do
  cd ~/dev/psiphi || error "no psiphi"
  /usr/bin/time -o ${here}/psiphi-raw.bench -a -f "${fmt}" \
    mpirun -n 4 ./PsiPhi > /dev/null || exit 1

  /usr/bin/time -o ${here}/psiphi-null.bench -a -f "${fmt}" \
    mpirun -n 4 \
    ${here}/inmemorysitu -null \
    ./PsiPhi > /dev/null || exit 1

  /usr/bin/time -o ${here}/psiphi-mt.bench -a -f "${fmt}" \
    mpirun -n 4 \
    ${here}/inmemorysitu -mt \
    ./PsiPhi > /dev/null || exit 1

  /usr/bin/time -o ${here}/psiphi-v2d.bench -a -f "${fmt}" \
    xs mpirun -n 4 \
    ${here}/inmemorysitu -size 32760 -v2d \
    ./PsiPhi > /dev/null || exit 1

  cd ${here} || error "could not return to ${here}"
  /usr/bin/time -o ${here}/relax-raw.bench -a -f "${fmt}" \
    testprograms/relax -x 40 -y 40 > /dev/null || exit 1

  /usr/bin/time -o ${here}/relax-null.bench -a -f "${fmt}" \
    ${here}/inmemorysitu -null \
    testprograms/relax -x 40 -y 40 > /dev/null || exit 1

  /usr/bin/time -o ${here}/relax-mt.bench -a -f "${fmt}" \
    ${here}/inmemorysitu -mt \
    testprograms/relax -x 40 -y 40 > /dev/null || exit 1

  /usr/bin/time -o ${here}/relax-v2d.bench -a -f "${fmt}" \
    xs ${here}/inmemorysitu -size 6000 -v2d \
    testprograms/relax -x 40 -y 40 > /dev/null || exit 1

  /usr/bin/time -o ${here}/linpack-raw.bench -a -f "${fmt}" \
    testprograms/linpack &> /dev/null || exit 1

  /usr/bin/time -o ${here}/linpack-null.bench -a -f "${fmt}" \
    ${here}/inmemorysitu -null \
    testprograms/linpack &> /dev/null || exit 1

  /usr/bin/time -o ${here}/linpack-mt.bench -a -f "${fmt}" \
    ${here}/inmemorysitu -mt \
    testprograms/linpack &> /dev/null || exit 1

  /usr/bin/time -o ${here}/linpack-v2d.bench -a -f "${fmt}" \
    xs ${here}/inmemorysitu -size 35000 -v2d \
    testprograms/linpack &> /dev/null || exit 1

  /usr/bin/time -o ${here}/nallocs-raw.bench -a -f "${fmt}" \
    testprograms/nallocs 7500 &> /dev/null || exit 1

  /usr/bin/time -o ${here}/nallocs-null.bench -a -f "${fmt}" \
    ${here}/inmemorysitu -null \
    testprograms/nallocs 7500 &> /dev/null || exit 1

  /usr/bin/time -o ${here}/nallocs-mt.bench -a -f "${fmt}" \
    ${here}/inmemorysitu -mt \
    testprograms/nallocs 7500 &> /dev/null || exit 1

  /usr/bin/time -o ${here}/nallocs-v2d.bench -a -f "${fmt}" \
    xs ${here}/inmemorysitu -size 42 -v2d \
    testprograms/nallocs 7500 &> /dev/null || exit 1
done
