# dump-index-android-bundle
Dump encrypted index.android.bundle at runtime

## Usage

```sh
# This script dumps index.android.bundle and outputs it on the current working directory
python3 ./main.py 'process name'
```

```sh
# This script dumps index.android.bundle on the android filesystem `/sdcard/Download/`
frida -U -f com.example -l ./dump-on-server.js
```
