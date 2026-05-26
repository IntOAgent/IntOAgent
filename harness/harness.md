| Project | Harness | Build configuration | sanitizer |
| --- | --- | --- | --- |
| SQLite | sqlite3 | `./configure \`<br>`  --enable-debug --enable-fts5 \`<br>`  CFLAGS="-O0 -g \`<br>`    -fsanitize=address,undefined \`<br>`    -fno-sanitize-recover=all \`<br>`    -fno-omit-frame-pointer \`<br>`    -DSQLITE_MAX_SQL_LENGTH=2000000000 \`<br>`    -DSQLITE_MAX_LENGTH=2000000000" \`<br>`  LDFLAGS="-fsanitize=address,undefined" \`<br>`&& make` | UBSan |
| Libxml2 | xmllint | `./configure --disable-shared \`<br>`  "CFLAGS=-O0 -g \`<br>`    -fsanitize=undefined,address,signed-integer-overflow \`<br>`    -fno-sanitize-recover=all" \`<br>`&& make` | UBSan |
| Libplist | plistutil | `./configure --disable-shared \`<br>`  "CFLAGS=-O0 -g \`<br>`    -fsanitize=undefined,address,signed-integer-overflow \`<br>`    -fno-sanitize-recover=all" \`<br>`&& make` | UBSan |
| Libplist | harness_plist.c | `./configure --disable-shared \`<br>`  "CFLAGS=-O0 -g \`<br>`    -fsanitize=undefined,address,signed-integer-overflow \`<br>`    -fno-sanitize-recover=all" \`<br>`&& make`<br><br>`gcc-11 -c src/base64.c \`<br>`  -o /tmp/libplist_base64_poc.o \`<br>`  -fsanitize=address,signed-integer-overflow \`<br>`  -I/home/xxx/lib/include \`<br>`  -I/home/xxx/libplist/src`<br><br>`gcc-11 -o poc harness_plist.c /tmp/libplist_base64_poc.o \`<br>`  -fsanitize=address,signed-integer-overflow \`<br>`  -I/home/xxx/lib/include \`<br>`  -I/home/xxx/libplist/src \`<br>`  -L/home/xxx/lib/lib \`<br>`  -lplist-2.0 \`<br>`  -Wl,-rpath,/home/xxx/lib/lib` | UBSan |
| V8 | d8 | `tools/dev/v8gen.py x64.debug --args="is_ubsan=true is_clang=true" && ninja -C out.gn/x64.debug` | UBSan |
| Libpng | pngtest | `./configure --disable-shared \`<br>`  "CFLAGS=-O0 -g \`<br>`    -fsanitize=undefined,address,signed-integer-overflow \`<br>`    -fno-sanitize-recover=all" \`<br>`&& make` | UBSan |
| Libpng | pnm2png | `CFLAGS="-m32 -O0 -g -fsanitize=address" CPPFLAGS="-m32" LDFLAGS="-m32" \`<br>`./configure --disable-shared --enable-static`<br>`&& make`<br><br>`gcc -m32 -g -O0 -fsanitize=address \`<br>`  -I. \`<br>`  -Icontrib/pngminus \`<br>`  contrib/pngminus/pnm2png.c \`<br>`  -L.libs -lpng18 -lz -lm \`<br>`  -o /tmp/pnm2png-32` | UBSan |

The harnesses listed above correspond to the harness files used for each project. The `pnm2png` harness comes from the original Libpng repository, but it is not linked into `pngtest`, so we additionally compiled the existing C file to invoke the relevant code paths. 

The `harness_plist.c` harness is a custom C harness because the native `plistutil` binary does not reach some target functions, so an additional manually written C file is compiled to call those functions. 

All other harnesses are provided by their respective upstream projects.
