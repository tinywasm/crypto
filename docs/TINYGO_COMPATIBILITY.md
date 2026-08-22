# Compatibilidad con TinyGo

> Este documento está en español por petición explícita. El resto de la
> documentación del repo sigue en inglés.

`tinywasm/crypto` promete "TinyGo Optimized / WebAssembly Ready". Este
documento **verifica esa promesa con evidencia**, no con suposiciones, y deja
registrada la decisión sobre qué paquetes del stdlib se usan y cuáles se
implementan en casa.

Última verificación: **2026-08-22**, TinyGo `0.41.1` (Go 1.25.2, LLVM 20.1.1),
target `wasm` — incluye los subpaquetes `crypto/subtle`, `crypto/blowfish`,
`crypto/bcrypt` y `crypto/rand`.

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
→ vet ✅, race ✅, tests ✅, wasm ✅, coverage: 90.5% (146.2s)
```

Esto ejercita `Encrypt`/`Decrypt` (AES-GCM), `GenerateKeyPair`,
`EncryptAsymmetric`/`DecryptAsymmetric` (ECDH), `Sign`/`Verify` (ECDSA),
`ConstantTimeCompare` (`subtle`), el cifrador `blowfish` contra sus vectores
publicados, y `bcrypt.GenerateFromPassword`/`CompareHashAndPassword`
(incluida interoperabilidad con hashes de `golang.org/x/crypto/bcrypt`), con
sus casos de error.

`TestCostValidation` queda marcado `⚠️ slow` (6.6s): es el único test que
necesita correr un hash a `DefaultCost` de verdad (valida que un coste por
debajo del mínimo cae a `DefaultCost`), así que su costo es inherente, no un
descuido — el resto de los tests de `bcrypt` usan `bcrypt.MinCost` por la
regla anti-footgun del plan.

## Tabla de compatibilidad

| Paquete stdlib | Usado en | TinyGo | Decisión |
|---|---|---|---|
| `crypto/aes`, `crypto/cipher` | `tinycrypto.go` (AES-GCM) | ✅ compila y pasa | usar stdlib |
| `crypto/ecdsa`, `crypto/elliptic` | `tinycrypto.go` (firmas) | ✅ compila y pasa | usar stdlib |
| `crypto/ecdh` | `tinycrypto.go` (cifrado asimétrico) | ✅ compila y pasa | usar stdlib |
| `crypto/x509` | `tinycrypto.go` (serialización de claves) | ✅ compila y pasa | usar stdlib |
| `crypto/sha256` | `tinycrypto.go`, `hmac.go` | ✅ compila y pasa | usar stdlib |
| `crypto/rand` | `rand/rand_native.go` (`!wasm`) | n/a — no entra en el binario wasm | usar stdlib, aislado en subpaquete `crypto/rand` para que `bcrypt`/`blowfish` no importen la raíz |
| `crypto/hmac` | `hmac.go` | ✅ compila y pasa | usar stdlib |
| `crypto/subtle` (raíz de este repo, no confundir con el stdlib `crypto/subtle`) | `subtle/subtle.go` | ✅ compila y pasa | implementación propia sin ningún import — ni siquiera `tinywasm/fmt` |
| `encoding/base64` | base64url para JWT | ✅ compila | **sustituido** por `tinywasm/base64` (cero deps, −31 KB) — ver abajo |
| `golang.org/x/crypto/blowfish` (no es stdlib) | `blowfish/cipher.go` | ✅ compila y pasa | **portado** a `crypto/blowfish` — ver sección siguiente |
| `golang.org/x/crypto/bcrypt` (no es stdlib) | `bcrypt/bcrypt.go` | ✅ compila y pasa | **portado** a `crypto/bcrypt` — ver sección siguiente |

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

## `bcrypt`/`blowfish`: por qué se portaron en vez de usar `golang.org/x/crypto`

`golang.org/x/crypto/bcrypt` y `golang.org/x/crypto/blowfish` compilan bajo
TinyGo, pero **no son stdlib**: son un módulo aparte, y su cadena de imports
arrastra `fmt`, `strconv`, `errors`, `io`, `unicode`, `reflect` y
`encoding/base64` — exactamente lo que este repo existe para evitar. Medido en
`veltylabs/misitio` (Worker de Cloudflare): esa cadena cuesta 109 664 bytes,
15 % del binario. Por eso se portaron a `crypto/bcrypt` y `crypto/blowfish`
como subpaquetes hoja, sin ninguna de esas dependencias.

### La trampa se repitió: medir de verdad, no solo `go list -deps`

El primer intento de `crypto/bcrypt` llamaba a `crypto.Random` de la **raíz**
de este repo para la sal. `go build`/`go vet`/`gotest` pasaban en verde. Pero
la raíz ya importa `crypto/aes`, `crypto/x509`, `crypto/ecdsa`,
`crypto/elliptic` (ver tabla arriba) — y Go compila un paquete como una sola
unidad, así que ese único import arrastró todo eso, más `fmt`/`reflect` que
esas primitivas necesitan.

Medido con `tinygo build -target=wasm -no-debug -opt=z` de un programa mínimo
que solo llama a `bcrypt.GenerateFromPassword`:

| Versión | Binario |
|---|---|
| primer intento (`bcrypt` importa la raíz `crypto`) | 285 486 bytes — **53 % más grande** que `golang.org/x/crypto/bcrypt` |
| corregido (`bcrypt` importa `crypto/rand`, no la raíz) | 65 620 bytes — **65 % más chico** que `golang.org/x/crypto/bcrypt` |
| `golang.org/x/crypto/bcrypt` (referencia) | 186 185 bytes |

El primer número invertía por completo el propósito del paquete: un
`go list -deps` sobre `./bcrypt/` ya lo habría delatado (mostraba
`fmt, strconv, errors, io, bytes, unicode, reflect, encoding/base64`), pero el
número real solo salió a la luz al compilar de verdad con TinyGo. **La lección
de la sección anterior se repite aquí**: ni siquiera un import de una sola
línea a dentro del propio repo está exento de medirse.

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
