# TlsPublisher for peach

This peach publisher is a drop in replacement for the Tcp Client and Server
Publishers for fuzzing applications which communicate over TLS.

## Building

```
git clone https://github.com/pdxjohnny/TlsPublisher
cd TlsPublisher
# Or whereever you installed peach
export PEACH=/usr/share/peach
dmcs TlsPublisher.cs -out:TlsPublisher.dll -target:library -r:${PEACH}/Peach.Core.dll,${PEACH}/NLog.dll
ln -s $PWD/TlsPublisher.dll $PEACH/
```

Thats all there is to it! Now you can just replace Tcp with Tls in your pit.
