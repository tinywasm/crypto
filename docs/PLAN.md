---
PLAN: "fix(rand): report CSPRNG failures on wasm and add rand.Secret/rand.Bytes"
EXECUTOR: jules
REVIEWER: none
---

> Este plan se despacha con el flujo CodeJob. Ver skill: `agents-workflow`.
> No ejecutes `gopush` ni `codejob` — son herramientas del desarrollador local.

# PLAN — `tinywasm/crypto`: aleatoriedad que falla ruidosamente

## Contexto

Auditoría de seguridad de `veltylabs/iam` (2026-09-02). `tinywasm/auth` va a
pasar a derivar de aquí los ids de sesión y los `state` de OAuth (hoy usa
timestamps predecibles). Antes de eso, `rand` tiene que ser confiable y tiene
que ofrecer el generador de secretos que hoy cada consumidor arma a mano.

Doctrina obligatoria: [CONSTRUCTION_HARNESS.md](https://github.com/tinywasm/app-releases/blob/main/docs/CONSTRUCTION_HARNESS.md).
Los principios que gobiernan este plan:

- **6 · Fallar en compilación, no en runtime.** Orden de preferencia:
  error de compilación → diagnóstico ruidoso → (nunca) fallo silencioso.
- **9 · Piezas lego.** El generador de secretos se escribe una vez, en la
  librería que lo posee — no en cada consumidor.

## Hallazgos

### C-1 (Medio) · `rand.Read` en wasm nunca falla

`rand/rand_wasm.go` (build tag `wasm`) hoy es:

```go
func Read(b []byte) error {
	uint8Array := js.Global().Get("Uint8Array").New(len(b))
	js.Global().Get("crypto").Call("getRandomValues", uint8Array)
	js.CopyBytesToGo(b, uint8Array)
	return nil
}
```

Tres fallos silenciosos:

1. No verifica que `globalThis.crypto` exista. Si no está, `Call` entra en
   pánico dentro del Worker en vez de devolver un error.
2. `crypto.getRandomValues` **lanza `QuotaExceededError` si `len(b) > 65536`**.
   El `Call` propaga esa excepción como pánico de `syscall/js`.
3. Devuelve `nil` siempre. Un consumidor que escribe
   `if err := rand.Read(buf); err != nil { … }` cree estar chequeando algo y
   no chequea nada — exactamente el fallo silencioso que el principio 6 prohíbe.

### C-2 (Medio) · Falta el generador de secretos

`veltylabs/iam` hace hoy, a mano:

```go
buf := make([]byte, 30)
if err := rand.Read(buf); err != nil { return "", err }
return "iam_sk_" + base64.URLEncode(buf), nil
```

y `tinywasm/auth` va a necesitar lo mismo para los ids de sesión y los `state`
de OAuth. Es glue idéntico repetido en cada consumidor: pertenece a la pieza
que posee la aleatoriedad (principio 9).

## Etapa 1 · `rand.Read` reporta fallos (wasm)

Archivo: `rand/rand_wasm.go` (o el nombre actual del archivo con `//go:build wasm`).

Reescribir `Read` para que:

1. Devuelva `nil` inmediatamente si `len(b) == 0`.
2. Recupere `globalThis.crypto` y, si es `IsNull()` o `IsUndefined()`,
   devuelva `ErrNoCSPRNG`.
3. Verifique que `crypto.getRandomValues` sea una función
   (`.Type() == js.TypeFunction`); si no, `ErrNoCSPRNG`.
4. Llene `b` **en trozos de a lo sumo `maxChunk` bytes**, para no cruzar el
   límite de la plataforma.
5. Envuelva la llamada a `getRandomValues` en `defer func() { recover() }`
   para convertir la excepción de JS en `ErrCSPRNGFailed` en vez de en pánico.

Constantes y errores nuevos, exportados, en un archivo compartido por ambos
build tags — crear `rand/errors.go` **sin** build tag:

```go
package rand

import "github.com/tinywasm/fmt"

// maxChunk es el máximo que crypto.getRandomValues acepta por llamada
// (WebCrypto lanza QuotaExceededError por encima). Read pide de a trozos.
const maxChunk = 65536

// ErrNoCSPRNG: el entorno no expone un generador criptográfico. Nunca se
// degrada a una fuente débil: sin aleatoriedad real no hay secreto que valga.
var ErrNoCSPRNG = fmt.Err("rand", "csprng", "unavailable")

// ErrCSPRNGFailed: el generador existe pero rechazó la petición.
var ErrCSPRNGFailed = fmt.Err("rand", "csprng", "failed")
```

Mensajes exactos: `rand csprng unavailable` y `rand csprng failed`.

**Anti-footgun:** `rand/rand_native.go` (`//go:build !wasm`) ya delega en
`crypto/rand` de la stdlib y **está bien así** — este repo es la frontera
criptográfica y usa la stdlib legítimamente. No "arregles" ese archivo ni le
quites el import de `crypto/rand`.

## Etapa 2 · `rand.Bytes` y `rand.Secret`

Archivo nuevo: `rand/secret.go`, sin build tag (usa `Read`, que sí lo tiene).

```go
package rand

import "github.com/tinywasm/base64"

// DefaultSecretBytes es la entropía de un secreto generado por Secret: 32
// bytes = 256 bits, el mismo orden que una clave HS256. Menos que esto vuelve
// el secreto adivinable; más no compra nada.
const DefaultSecretBytes = 32

// Bytes devuelve n bytes criptográficamente aleatorios. Devuelve error —
// nunca un slice a medio llenar ni ceros — porque un secreto silenciosamente
// débil es peor que no tener secreto.
func Bytes(n int) ([]byte, error)

// Secret devuelve DefaultSecretBytes bytes aleatorios codificados en base64
// url-safe: la forma lista para viajar en una cookie, un state de OAuth o un
// client_secret. Es el ÚNICO camino para producir un secreto en este
// ecosistema — un consumidor nunca vuelve a escribir make([]byte,n)+Read+encode.
func Secret() (string, error)

// SecretN es Secret con una entropía explícita, para el caso raro en que el
// formato de destino impone un largo. n <= 0 usa DefaultSecretBytes.
func SecretN(n int) (string, error)
```

`Bytes` devuelve `nil, ErrInvalidLength` si `n <= 0`. Constante nueva en
`rand/errors.go`:

```go
// ErrInvalidLength: pedir 0 o menos bytes aleatorios siempre es un bug del
// llamador, nunca una petición válida.
var ErrInvalidLength = fmt.Err("rand", "length", "must-be-positive")
```

Mensaje exacto: `rand length must-be-positive`.

## Etapa 3 · Tests

Archivo: `rand/rand_test.go` (extender) y `rand/secret_test.go` (nuevo).
Ambos con `//go:build !wasm` **sólo si** hoy los tests del paquete lo tienen;
si no, sin build tag.

Casos obligatorios:

| Test | Verifica |
|---|---|
| `TestBytesRejectsNonPositive` | `Bytes(0)` y `Bytes(-1)` → `ErrInvalidLength`, slice `nil`. |
| `TestBytesLength` | `Bytes(1)`, `Bytes(32)`, `Bytes(65537)` devuelven exactamente ese largo. `65537` prueba el troceado. |
| `TestBytesNotAllZero` | 32 bytes pedidos dos veces no son iguales y no son todos cero. |
| `TestSecretIsURLSafe` | `Secret()` no contiene `+`, `/` ni `=`; decodifica con `base64.URLDecode` a `DefaultSecretBytes` bytes. |
| `TestSecretUnique` | 100 llamadas a `Secret()` → 100 valores distintos (búsqueda lineal sobre un slice; **no uses `map`**, ver más abajo). |
| `TestSecretNDefaultsOnNonPositive` | `SecretN(0)` y `SecretN(-5)` producen el mismo largo que `Secret()`. |

**Test consumer-shaped obligatorio** (regla de oro del harness: *an API is not
published until a consumer-shaped test, inside the library itself, proves it*).
En `rand/secret_test.go`:

```
TestSecret_ShapedLikeASessionToken
```

Debe generar 1000 secretos, verificar que ninguno se repite, y que ninguno es
**prefijo** de otro (un token enumerable por prefijo es el defecto que este
plan existe para cerrar en `tinywasm/auth`).

## Etapa 4 · Documentación

- `docs/hashing.md` o `docs/IMPLEMENTATION.md` (el que hoy cubra `rand`):
  agregar una sección **"Aleatoriedad"** con la tabla "quiero X → uso Y":

  | Quiero | Uso |
  |---|---|
  | Un secreto listo para cookie/state/client_secret | `rand.Secret()` |
  | Un secreto con largo impuesto por el formato | `rand.SecretN(n)` |
  | Bytes crudos para una clave | `rand.Bytes(n)` |
  | Llenar un buffer que ya tengo | `rand.Read(b)` |

- Documentar que `Read` **puede** fallar en wasm y que el consumidor debe
  propagar el error, nunca ignorarlo.
- `README.md`: agregar `rand.Secret()` al ejemplo de uso si hay uno.

## Restricciones de código (leer antes de escribir)

| Regla | Detalle |
|---|---|
| **Sin mapas** | Prohibido `map[K]V` en código de librería y en tests. Slices + búsqueda lineal. TinyGo compila mapas mal e infla el binario. |
| **Sin stdlib pesada** | Nada de `fmt`, `errors`, `strconv`, `strings`, `log`, `os`. Usa `github.com/tinywasm/fmt`. **Excepción vigente:** `rand/rand_native.go` usa `crypto/rand` y `hmac/`/`subtle/` usan `crypto/*` — es la frontera criptográfica del ecosistema, es deliberado, NO lo toques. |
| **`error` sí, `errors` no** | Devolver `error` está bien; construirlo con `errors.New` no. Usa `fmt.Err(...)`. |
| **Sin `reflect`** | En ninguna forma, ni transitiva. |
| **Sin literales repetidos** | Todo string repetido (mensaje de error, prefijo) es una constante nombrada y exportada. Prohibidos los literales en la lógica. |
| **Sin `internal/`** | No crees carpetas `internal/`. |

Idioma: **código e identificadores en inglés**; **comentarios de prosa y
documentación en español**.

## Criterios de aceptación

1. `go vet ./...` y `go test ./...` verdes.
2. `grep -rn "return nil$" rand/rand_wasm.go` → no queda un `return nil`
   incondicional al final de `Read`.
3. `grep -rn "map\[" rand/` → vacío.
4. `rand.Secret`, `rand.SecretN`, `rand.Bytes`, `ErrNoCSPRNG`,
   `ErrCSPRNGFailed`, `ErrInvalidLength`, `DefaultSecretBytes` exportados y
   documentados con comentario en español.
5. Compila para wasm: `GOOS=js GOARCH=wasm go build ./...`.
6. `TestSecret_ShapedLikeASessionToken` existe y pasa.

## Etapas

| # | Archivo | Entrega |
|---|---|---|
| 1 | `rand/rand_wasm.go`, `rand/errors.go` | `Read` reporta fallos y trocea a 65536 B |
| 2 | `rand/secret.go` | `Bytes`, `Secret`, `SecretN` |
| 3 | `rand/rand_test.go`, `rand/secret_test.go` | Tests, incluido el consumer-shaped |
| 4 | `docs/`, `README.md` | Tabla "quiero X → uso Y" |
