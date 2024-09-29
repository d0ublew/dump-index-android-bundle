# dump-index-android-bundle
Dump encrypted index.android.bundle at runtime

## Usage

```sh
# This script dumps index.android.bundle and outputs it on the current working directory
python3 ./main.py spawn 'com.example.foo'
python3 ./main.py attach 'foo app'
```

```sh
# This script dumps index.android.bundle on the android filesystem `/sdcard/Download/`
frida -U -f com.example.foo -l ./dump-on-server.js
frida -U -N com.example.foo -l ./dump-on-server.js
```
