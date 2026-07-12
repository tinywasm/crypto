# Compatibilidad con TinyGo

> Este documento está en español por petición explícita. El resto de la
> documentación del repo sigue en inglés.

`tinywasm/crypto` promete "TinyGo Optimized / WebAssembly Ready". Este
documento **verifica esa promesa con evidencia**, no con suposiciones, y deja
registrada la decisión sobre qué paquetes del stdlib se usan y cuáles se
implementan en casa.

Última verificación: **2026-07-12**, TinyGo `0.41.1` (Go 1.25.2, LLVM 20.1.1),
target `wasm`.

## Por qué había que medirlo

La suite verde **no probaba nada** sobre TinyGo. `gotest` compilaba el bloque
WASM con el toolchain estándar de Go (`GOOS=js GOARCH=wasm` + `wasmbrowsertest`),
y el backend `js/wasm` de Go soporta **todo** el stdlib. Es decir: un paquete que
TinyGo rechaza puede tener la suite WASM en verde igualmente.

Para cerrar ese agujero se añadió el flag `-tinygo`:

- `wasmbrowsertest -tinygo` — recompila el paquete con TinyGo (el binario que le
  entrega `go test -exec` viene del compilador de Go y por tanto no demuestra
  nada) y sirve el `wasm_exec.js` **de TinyGo**, que no es intercambiable con el
  de Go: cada toolchain emite imports de host distintos.
- `gotest -tinygo` — pasa esa bandera a la suite WASM.

```bash
gotest -tinygo     # compila el bloque WASM con TinyGo y lo corre en navegador
```

Es **opt-in** porque es lento: TinyGo pasa por LLVM y tarda ~2 órdenes de
magnitud más que `go build` (esta librería: ~125 s frente a ~2 s).

## Resultado: la librería entera pasa con TinyGo

Ejecutado de punta a punta (compilación TinyGo real + navegador real):

```
cd crypto && gotest -tinygo
→ vet ✅, race ✅, tests ✅, wasm ✅, coverage: 80.6% (124.2s)
```

Esto ejercita `Encrypt`/`Decrypt` (AES-GCM), `GenerateKeyPair`,
`EncryptAsymmetric`/`DecryptAsymmetric` (ECDH) y `Sign`/`Verify` (ECDSA), con sus
casos de error.

## Tabla de compatibilidad

| Paquete stdlib | Usado en | TinyGo | Decisión |
|---|---|---|---|
| `crypto/aes`, `crypto/cipher` | `tinycrypto.go` (AES-GCM) | ✅ compila y pasa | usar stdlib |
| `crypto/ecdsa`, `crypto/elliptic` | `tinycrypto.go` (firmas) | ✅ compila y pasa | usar stdlib |
| `crypto/ecdh` | `tinycrypto.go` (cifrado asimétrico) | ✅ compila y pasa | usar stdlib |
| `crypto/x509` | `tinycrypto.go` (serialización de claves) | ✅ compila y pasa | usar stdlib |
| `crypto/sha256` | `tinycrypto.go` | ✅ compila y pasa | usar stdlib |
| `crypto/rand` | `random_native.go` (`!wasm`) | n/a — no entra en el binario wasm | usar stdlib |
| `crypto/hmac` | *pendiente* (`hmac.go`, ver PLAN) | ✅ compila | usar stdlib |
| `crypto/subtle` | *pendiente* (comparación constante) | ✅ compila | usar stdlib |
| `encoding/base64` | base64url para JWT | ✅ compila | **sustituido** por `tinywasm/base64` (cero deps, −31 KB) — ver abajo |

**Conclusión sobre la pregunta original:** no hace falta copiar ni reimplementar
ninguna primitiva criptográfica. Todo el `crypto/*` que usa (y usará) esta
librería es 100 % compatible con TinyGo. Reimplementar AES o SHA en Go sería más
lento y menos seguro, sin ganancia alguna.

## La única excepción: `encoding/base64` → `tinywasm/base64`

Es compatible con TinyGo, así que **no se descarta por compatibilidad sino por
tamaño**. Vive ahora en su propio paquete de cero dependencias,
[`github.com/tinywasm/base64`](https://github.com/tinywasm/base64)
(`URLEncode` / `URLDecode`), reutilizable por cualquier consumidor del ecosistema.

Programa mínimo que codifica y decodifica, compilado con TinyGo a `wasm`:

| Implementación | Binario |
|---|---|
| `encoding/base64` | 154 115 bytes |
| `tinywasm/base64` | 122 967 bytes |
| **ahorro** | **31 148 bytes (20 %)** |

### La trampa: la dependencia puede costar más que el ahorro

La primera versión de `tinywasm/base64` importaba `tinywasm/fmt` solo para
declarar su valor de error. Resultado medido: **228 234 bytes, o sea 74 KB MÁS
grande que el stdlib** — la dependencia costaba cuatro veces más que todo lo que
el códec ahorraba. Quitando ese import (el error se declara con un tipo propio,
sin importar nada) el paquete pasó a ahorrar 31 KB de verdad.

**Reglas resultantes:**

1. El carve-out del stdlib cubre **primitivas criptográficas**, no codificaciones.
   `crypto/*` entra; `encoding/*` no.
2. Un paquete de utilidad para el edge solo compensa si es de **cero
   dependencias**. Sustituir stdlib por una librería propia que a su vez arrastra
   `tinywasm/fmt` puede salir *más caro* que el stdlib. **Medir siempre, nunca
   asumir.**

## Cómo reproducir estas mediciones

```bash
# 1. Suite completa bajo TinyGo real
gotest -tinygo

# 2. Coste en bytes de un import (sustituir por el paquete a evaluar)
tinygo build -o base.wasm -target wasm ./   # sin el import
tinygo build -o con.wasm  -target wasm ./   # con el import
stat -c '%s %n' base.wasm con.wasm
```

Si TinyGo no está instalado, `wasmbrowsertest -tinygo` falla con instrucciones:
`go run github.com/tinywasm/tinygo/cmd/tinygoinstall@latest`.

## Al añadir una dependencia nueva

1. Compilar con `gotest -tinygo`. Si TinyGo la rechaza, **no** se trabaja alrededor
   en el consumidor: o se sustituye, o se implementa en el ecosistema `tinywasm`.
2. Si compila, medir su coste en bytes con el método de arriba antes de darla por
   buena.
