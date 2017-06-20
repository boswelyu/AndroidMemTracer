echo %cd%
adb push "injector\libs\armeabi-v7a\memtrace" "/data/local/memtracer/"
adb push "libmemtracer\libs\armeabi-v7a\libmemtracer.so" "/data/local/memtracer/"
adb push "commander\libs\armeabi-v7a\commander" "/data/local/memtracer/"
adb shell su -c "chmod 777 /data/local/memtracer/*"
pause