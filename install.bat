echo %cd%
adb shell su -c "mkdir -p /data/local/memtracer/"
adb shell su -c "chmod 755 /data/local/memtracer/"
adb shell su -c "mkdir -p /sdcard/tmp/memtracer/"
adb shell su -c "chmod 555 /sdcard/tmp/memtracer/"
adb push "injector\libs\armeabi-v7a\memtrace" "/data/local/memtracer/"
adb push "libmemtracer\libs\armeabi-v7a\libmemtracer.so" "/data/local/memtracer/"
adb shell su -c "chmod 777 /data/local/memtracer/*"
pause