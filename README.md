# Hyperfent

After writing an emulator and unpacker for the [Hypertech crackproof](https://www.hypertech.co.jp/products/windows/) DRM, I've decided to cook up this small example that shows how to abuse their signed driver to protect your own processes. The driver allows you to arbitarily flip bits inside the EPROCESS structure amongst some other things.