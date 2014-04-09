make || exit 1
./printcfg /tmp/hw -dot > out.dot || exit 1
xs dot -Tpng out.dot -o hw.png || exit 1
