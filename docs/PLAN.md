---
PLAN: "feat: blowfish, bcrypt y comparacion en tiempo constante como subpaquetes"
EXECUTOR: jules
REVIEWER: none
STATUS: review
SESSION: 17314158382481068538
PR: https://github.com/tinywasm/crypto/pull/5
---

> Este plan se despacha con el flujo CodeJob. Ver skill: agents-workflow.

# Plan — `tinywasm/crypto`: bcrypt nativo

## Por qué

`tinywasm/user/authority` hashea contraseñas con `golang.org/x/crypto/bcrypt`.
Ese paquete importa `fmt`, `strconv`, `errors` e `io` de la biblioteca estándar,
y con ellos entran `reflect`, `internal/fmtsort` y las tablas de Unicode.

Está **medido** sobre una aplicación real (`veltylabs/misitio`, Worker de
Cloudflare): sacar esa cadena del binario quita **109.664 bytes**, el 15 % del
Worker, más una página de 64 KB de RAM. En ese mismo binario `bcrypt` pesaba
888 bytes y `blowfish` 148: **el peso no es bcrypt, es la stdlib que arrastra.**

Por eso el remedio es reimplementar bcrypt sin la stdlib, no esconderlo detrás de
una interfaz: si el paquete no arrastra nada, `authority` puede seguir
importándolo como hoy y no se rompe ninguna API.

## Regla que gobierna todo este plan

**Subpaquetes, nunca el paquete plano.** Hoy `tinywasm/crypto` es un solo
paquete (`hmac.go`, `tinycrypto.go`, `random_*.go`). Si blowfish y bcrypt
entraran ahí, toda aplicación que use `crypto.HMACSHA256` enlazaría el cifrador y
el bucle de coste — que es exactamente la enfermedad que este plan cura.

Los tres subpaquetes nuevos son:

```
crypto/subtle/     — comparación en tiempo constante
crypto/blowfish/   — el cifrador
crypto/bcrypt/     — el hash de contraseñas
```

## Restricciones — aplican a los tres

1. **Nada de la biblioteca estándar.** Ni `fmt`, ni `errors`, ni `strconv`, ni
   `strings`, ni `io`, ni `bytes`. Para errores y formato, `github.com/tinywasm/fmt`.
2. **Sin `map[K]V`.** Arreglos de tamaño fijo y búsqueda lineal.
3. **Sin `reflect`.**
4. Código en inglés, comentarios de prosa en español.
5. Todo string repetido es una constante nombrada.

**Anti-footgun:** estas reglas aplican al código del paquete. Los `_test.go`
compilan con Go estándar y **usan la stdlib legítimamente** — `testing`,
`encoding/hex` para vectores de prueba, etc. No "arregles" sus imports.

---

## Etapa 1 — `crypto/subtle`

```go
// ConstantTimeCompare devuelve 1 si x e y son iguales, 0 si no. El tiempo de
// ejecución depende sólo de la longitud, nunca del contenido: comparar con un
// cortocircuito filtra por cuántos bytes coinciden y con eso se reconstruye un
// hash byte a byte.
func ConstantTimeCompare(x, y []byte) int

// ConstantTimeByteEq devuelve 1 si x == y, 0 si no.
func ConstantTimeByteEq(x, y uint8) int
```

Sin dependencias, ni siquiera `tinywasm/fmt`.

**Y refactoriza `HMACEqual` de la raíz para que use `subtle.ConstantTimeCompare`**
en vez de su comparación propia. Es la misma primitiva y tenerla dos veces es la
duplicación que este plan existe para quitar. `HMACEqual` **conserva su firma**.

Test: dos slices iguales → 1; distintos en el primer byte → 0; distintos en el
último → 0; longitudes distintas → 0; ambos vacíos → 1.

---

## Etapa 2 — `crypto/blowfish`

Puerto de `golang.org/x/crypto/blowfish`. Es un cifrador de bloque de 8 bytes con
un calendario de claves caro — que es justo lo que le da valor a bcrypt.

API mínima, **sólo lo que bcrypt necesita**:

```go
type Cipher struct {
	p  [18]uint32
	s0, s1, s2, s3 [256]uint32
}

func NewCipher(key []byte) (*Cipher, error)
func NewSaltedCipher(key, salt []byte) (*Cipher, error)
func (c *Cipher) Encrypt(dst, src []byte)
func (c *Cipher) Decrypt(dst, src []byte)
func ExpandKey(key []byte, c *Cipher)
```

**No implementes `cipher.Block` ni ningún modo de operación** (CBC, CTR, GCM):
bcrypt usa el cifrado de bloque desnudo y todo lo demás sería peso muerto.

Las cajas S y el arreglo P iniciales son **tablas constantes de dígitos de π**.
Cópialas literalmente del original —son datos, no lógica— a un archivo aparte,
`const.go`, para que el código legible no quede sepultado bajo 1.042 números.

**Presupuesto:** esas tablas son 4×256 + 18 `uint32` ≈ **4,2 KB de datos
estáticos** que hoy no están en ningún binario. Es el único coste nuevo de todo
este plan y hay que medirlo (ver criterios).

Errores con `tinywasm/fmt`, como constantes:

```go
const ErrKeySize = "blowfish: longitud de clave no válida"
```

Tests: los vectores de prueba de `golang.org/x/crypto/blowfish` se copian tal
cual (`blowfish_test.go` del original) — son vectores publicados y son la única
forma seria de comprobar un cifrador. Adapta sólo los imports.

---

## Etapa 3 — `crypto/bcrypt`

Puerto de `golang.org/x/crypto/bcrypt` (589 líneas en total, incluido su base64).

```go
const (
	MinCost     int = 4
	MaxCost     int = 31
	DefaultCost int = 10
)

func GenerateFromPassword(password []byte, cost int) ([]byte, error)
func CompareHashAndPassword(hashedPassword, password []byte) error
func Cost(hashedPassword []byte) (int, error)
```

Las tres firmas son **idénticas a las del original**, para que `tinywasm/user`
cambie sólo la línea del import.

### Sustituciones respecto del original

| El original usa | Aquí se usa |
|---|---|
| `crypto/rand` | `crypto.Random(b []byte) error` — **ya existe en la raíz de este repo** (`random_wasm.go` / `random_native.go`) |
| `crypto/subtle` | `crypto/subtle` de la etapa 1 |
| `encoding/base64` con alfabeto propio | `github.com/tinywasm/base64` con `NewEncoding(...)` |
| `fmt`, `errors`, `strconv` | `github.com/tinywasm/fmt` |
| `io` (sólo para `io.Reader` de la sal) | nada: la sal sale de `crypto.Random` |

**Sobre la aleatoriedad:** la raíz de este repo ya resuelve el problema por
target — en el navegador llama a `crypto.getRandomValues`. Si la función no está
exportada con un nombre utilizable desde un subpaquete, expórtala en la raíz como
`func Random(b []byte) error` y que `readRandom` pase a ser su implementación.
**No copies `random_wasm.go` dentro de `bcrypt`.**

**Sobre base64:** `github.com/tinywasm/base64` v0.0.5 ya publica
`NewEncoding(alphabet string, pad bool) (*Encoding, error)`. El alfabeto de
bcrypt es `"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"`
**sin relleno**. No escribas una cuarta tabla base64 aquí.

### Errores

```go
const (
	ErrHashTooShort         = "bcrypt: el hash es demasiado corto"
	ErrMismatchedHashAndPassword = "bcrypt: el hash no corresponde a la contraseña"
	ErrCostTooLow           = "bcrypt: coste %d por debajo del mínimo %d"
	ErrCostTooHigh          = "bcrypt: coste %d por encima del máximo %d"
	ErrHashVersionTooNew    = "bcrypt: versión de hash '%c' no soportada"
	ErrPasswordTooLong      = "bcrypt: la contraseña supera los 72 bytes"
)
```

`CompareHashAndPassword` **tiene que devolver un error distinguible** cuando la
contraseña no coincide: los consumidores comparan contra él. Expón un centinela
comparable con `==`, no un error construido en cada llamada.

### Tests

Copia `bcrypt_test.go` del original. Son los que importan: incluyen hashes
generados por otras implementaciones de bcrypt, y **eso es lo único que
demuestra que este puerto es compatible con lo ya almacenado en producción**.

Añade además:

| Caso | Espera |
|---|---|
| hash generado aquí, verificado aquí | correcto |
| hash del original de `x/crypto` (fijo en el test), verificado aquí | correcto |
| contraseña equivocada | el centinela de no-coincidencia, comparable con `==` |
| `cost` 3 y 32 | `ErrCostTooLow` / `ErrCostTooHigh` |
| contraseña de 73 bytes | `ErrPasswordTooLong` |
| dos hashes de la misma contraseña | **distintos** (la sal es aleatoria) |
| `Cost()` sobre un hash de coste 12 | 12 |

**Anti-footgun:** bcrypt con `DefaultCost` tarda ~100 ms por hash a propósito.
Un test que genere veinte hashes con el coste por defecto tarda dos segundos.
Usa `MinCost` en todo test que no esté midiendo el coste.

---

## Criterios de aceptación

- [ ] `GOOS=js GOARCH=wasm go list -deps ./bcrypt/` **no contiene** `fmt`,
      `strconv`, `errors`, `io`, `bytes`, `unicode`, `reflect` ni `encoding/base64`.
- [ ] Lo mismo para `./blowfish/` y `./subtle/`.
- [ ] `grep -rn "map\[" bcrypt/ blowfish/ subtle/` → vacío fuera de `_test.go`.
- [ ] Los vectores de prueba del original pasan sin modificar sus valores.
- [ ] Un hash producido por `golang.org/x/crypto/bcrypt` se verifica
      correctamente aquí. **Es el criterio que decide si el puerto sirve**: si
      falla, todas las contraseñas guardadas quedan inservibles.
- [ ] `HMACEqual` conserva su firma y ahora delega en `subtle`.
- [ ] La raíz `tinywasm/crypto` **no gana dependencias**: sigue con
      `github.com/tinywasm/fmt` y nada más.
- [ ] Un programa mínimo que sólo llama a `crypto.HMACSHA256`, compilado con
      `tinygo build -target=wasm -no-debug -opt=z`, **no crece** respecto de hoy.
      Es lo que demuestra que los subpaquetes no contaminan la raíz. Escribe la
      cifra medida en el commit.
- [ ] Un programa mínimo que llama a `bcrypt.GenerateFromPassword` se mide y su
      cifra va en el `README.md`, junto a la comparación con
      `golang.org/x/crypto/bcrypt` en el mismo programa. Ese número es el
      argumento de existencia del paquete, igual que la tabla del README de
      `tinywasm/base64`.

## Fuera de alcance

scrypt, argon2, PBKDF2 y cualquier otro derivador de claves. Modos de operación
de blowfish. Nada de eso se construye hasta que alguien lo pida.
