# Linux x86_64 native libraries

The Docker build expects these two files to be here before `docker build .`:

```
libqudo_jni_crypto.so   # loaded by Spring Boot via -Djava.library.path
qudoprovider.so         # OpenSSL provider plugin (PQC algorithms, hybrid groups)
```

Both come from a **Linux x86_64 build of the `qudo-jni-crypto` repo** — the macOS
`.dylib` in the parent `libs/` directory is for local development only and won't
load inside the container.

## Where to get them

If you have access to the ZenV release artifacts, fetch the matching tarball:

```bash
# Replace 1.0.0 with whatever version the pom.xml's <qudo.version> points at.
curl -fL https://example.zenv.ai/qudo-pqc/qudo-pqc-v1.0.0-linux-x86_64.tar.gz | tar xz
cp qudo-pqc-v1.0.0-linux-x86_64/lib/libqudo_jni_crypto.so .
cp qudo-pqc-v1.0.0-linux-x86_64/ossl-modules/qudoprovider.so .
```

If you don't, build from source on a Linux host (Ubuntu 22.04+ or similar):

```bash
git clone https://github.com/ZenVInnovations/qudo-jni-crypto.git
cd qudo-jni-crypto
mkdir build && cd build
cmake .. && make -j
# Copy the two artifacts here:
#   build/libqudo_jni_crypto.so
#   build/qudoprovider.so
```

## Verifying

After `docker build`, sanity-check inside the running container:

```bash
docker run --rm -it qudo-portal-backend:1.0.0 sh -c '
  ldd /app/lib/libqudo_jni_crypto.so
  openssl list -providers -provider qudoprovider
'
```

Both should resolve cleanly; the `qudoprovider` line should show `status: active`.
