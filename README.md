# KVault Desktop

**KVault Desktop** es un gestor de credenciales y secretos de escritorio de alta densidad para entornos técnicos y de seguridad (**SecOps / DevSecOps**). Utiliza un formato de contenedor binario autenticado unificado (**`.kvlt` v2**), aislamiento criptográfico de secretos en memoria (**`ProtectedMemory`**), soporte opcional para llaves físicas **FIDO2 / U2F**, generador **2FA TOTP (RFC 6238)** integrado, motor nativo de **Auto-Type** y protección contra capturas de pantalla a nivel de ventana.

---

## ¿Qué es y cómo funciona?

A diferencia de los gestores basados en contenedores XML pesados o aplicaciones web empaquetadas que mantienen contraseñas como cadenas de texto plano inmutables en memoria, **KVault Desktop** opera bajo cinco pilares técnicos:

### 1. Contenedor Binario Unificado Autenticado (`.kvlt` v2)
Cada bóveda se almacena en un **único archivo binario compacto** con extensión `.kvlt` (sin archivos secundarios externos):
- **Cabecera Binaria y Hardware Key Slot Autenticados (AAD)**: Los primeros **62 bytes** de la cabecera junto con el bloque binario opcional de llave física (`H bytes` comprimidos con `DeflateRaw`) se inyectan como **Additional Authenticated Data (AAD)** dentro del cifrado autenticado. Si se altera un solo bit de la cabecera o del Key Slot en disco, la verificación del tag criptográfico (128 bits) aborta inmediatamente antes de descomprimir o procesar el contenido.
- **Doble Primitiva AEAD Seleccionable**:
  - `0x01` — **ChaCha20-Poly1305 (RFC 8439)**: Cifrado de flujo de 20 rondas autenticado con MAC Poly1305 sobre $GF(2^{130}-5)$.
  - `0x02` — **AES-256-GCM (NIST SP 800-38D)**: Cifrado por bloques acelerado por hardware (AES-NI) con autenticación Galois/Counter Mode.
- **Derivación de Clave Compuesta (Scrypt + KeyFile + DFA)**: Combina la Contraseña Maestra con un archivo llave opcional (**KeyFile**) y/o el factor de hardware mediante `SHA-512` / `HMAC-SHA256`, derivando la clave de 256 bits con **Scrypt** (`N=16384, r=8, p=1`).
- **Persistencia Transaccional Atómica**: Al guardar cambios, escribe primero en un archivo temporal (`.tmp.<pid>`), fuerza el volcado físico de buffers al disco mediante `fsync` y ejecuta un renombrado atómico (`rename`), evitando corrupción de la bóveda ante cierres bruscos o cortes de energía.

```text
Estructura binaria unificada del contenedor .kvlt (v2):
+-------------------+-------------------+-------------------+-------------------+
|  0..3 (4 bytes)   |   4 (1 byte)      |   5 (1 byte)      |  6..13 (8 bytes)  |
|  Magic: "KVLT"    |   Versión: 0x02   | Cipher: 0x01/0x02 | Scrypt (N, r, p)  |
+-------------------+-------------------+-------------------+-------------------+
|                         14..45 (32 bytes / 256 bits)                          |
|                         Salt Criptográfico Aleatorio                          |
+---------------------------------------+---------------------------------------+
|       46..57 (12 bytes / 96b)         |      58..61 (4 bytes / UInt32LE)      |
|           Nonce / IV AEAD             |   Longitud H del Hardware Key Slot    |
+---------------------------------------+---------------------------------------+
|                   62 .. 62+H-1 (H bytes, 0 si solo usa clave)                 |
|             Hardware Key Slot Binario (DeflateRaw + Protegido AAD)            |
+-------------------------------------------------------------------------------+
|                     62+H .. 78+H-1 (16 bytes / 128 bits)                      |
|                         Auth Tag AEAD (Poly1305 / GCM)                        |
+-------------------------------------------------------------------------------+
|                          78+H .. N (Longitud variable)                        |
|                  Payload JSON comprimido (GZip L9) + Cifrado AEAD             |
+-------------------------------------------------------------------------------+
|<--- Bytes 0 .. 62+H-1 protegidos criptográficamente con AAD --->|
```

### 2. Motor de Memoria Protegida (`ProtectedMemory`)
- Cuando una bóveda está desbloqueada, las contraseñas y semillas 2FA **no se mantienen en texto plano** ni se envían al proceso de interfaz (Renderer).
- Al hidratarse en el proceso principal, cada secreto se cifra inmediatamente en RAM con **ChaCha20-Poly1305** usando una clave efímera de sesión de 256 bits generada al azar.
- Cada vez que se requiere revelar o copiar un secreto, el buffer temporal se sobrescribe determinísticamente con ceros (`0x00` / patrón **Zeroize**) al concluir la operación. Al bloquear la bóveda (`Ctrl + L`), la clave efímera de sesión se destruye y rota.

### 3. Portapapeles Inteligente Win32 (Exclusión de `Win + V` + `ClearIfOwner`)
- **Exclusión del Historial `Win + V`**: Al copiar una contraseña, código 2FA o usuario, KVault abre una transacción directa con `user32.dll` (`OpenClipboard`) e inyecta simultáneamente las banderas nativas de Windows:
  - `ExcludeClipboardContentFromMonitorProcessing = 1`
  - `CanIncludeInClipboardHistory = 0`
  - `CanUploadToCloudClipboard = 0`
  - `Clipboard Viewer Ignore = 1`
  Esto permite pegar el secreto normalmente con `Ctrl + V`, pero **impide que el historial del portapapeles de Windows 10/11 (`Win + V`) y la sincronización en la nube lo capturen o almacenen**.
- **Limpieza Selectiva (`ClearIfOwner`)**: Transcurridos **12 segundos**, KVault verifica si el slot activo del portapapeles aún contiene el secreto que copió. Si coincide, limpia únicamente el slot activo (`EmptyClipboard`) **sin borrar ni alterar los demás textos que el usuario tenga guardados en su historial `Win + V`**. Si el usuario copió otro texto de trabajo durante esos 12 segundos, KVault respeta la nueva copia.

### 4. Protección Anti-Captura de Pantalla (`SetWindowDisplayAffinity`)
- La ventana de la aplicación activa `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` en el compositor gráfico de Windows (DWM) desde el arranque.
- Cualquier intento de captura de pantalla, recorte (`Win + Shift + S`) o grabación de escritorio omite o muestra en negro la ventana de KVault.

### 5. Autenticación Configurable (`Contraseña`, `Llave Física`, `DFA (Pass + Key)`)
- Integración nativa con `webauthn.dll` de Windows 10/11 para llaves físicas externas FIDO2 / U2F por USB o NFC, sin exponer metadatos descriptivos del dispositivo en la pantalla de bloqueo:
  1. **`Contraseña` (Por defecto)**: Apertura tradicional únicamente con Contraseña Maestra (y KeyFile opcional).
  2. **`DFA (Pass + Key)`**: Doble factor criptográfico estricto que exige **Contraseña Maestra + toque físico en la llave de seguridad** (`HMAC-SHA256` sobre factor de 256 bits desencapsulado tras verificar la firma **ECDSA P-256** del hardware).
  3. **`Llave Física`**: Apertura rápida con toque en la llave física (verificando firma **ECDSA P-256** + `ChaCha20-Poly1305` + `DPAPI`), manteniendo la Contraseña Maestra como llave de recuperación.

---

## Opciones y Funcionalidades Principales

- **Interfaz Utilitaria con Paneles Colapsables y Selector de Tema**:
  1. **Barra Superior de Herramientas**: Creación rápida de entradas y grupos, importación XML/CSV, generador CSPRNG, configuración `DFA / Key`, referencia de `Atajos`, selector de **Tema (`Auto (OS)`, `Oscuro`, `Claro`)** sincronizado con Windows y buscador instantáneo (`Ctrl + F`).
  2. **Panel Izquierdo Colapsable (`Árbol de Grupos` + `Auditoría`)**: Inicia colapsado en una barra vertical compacta (`▶ GRUPOS`) para ceder todo el ancho a la tabla principal, desplegándose con un clic para filtrar por grupos o consultar la **Auditoría de Seguridad** (total de entradas, entropía promedio en bits, claves débiles y registros con 2FA).
  3. **Panel Central (`DataGrid`)**: Tabla de alta densidad con indicadores de 2FA, nivel de entropía y acciones directas por celda con doble clic o menú contextual.
  4. **Inspector de Entrada Inferior Horizontal (Colapsable)**: Ubicado en la parte inferior en disposición horizontal de **4 columnas** (`Identificador & Título`, `Usuario & URL`, `Secreto en ProtectedMemory`, `2FA TOTP & Notas`). Inicia colapsado como una barra compacta (`▲ Inspector de Entrada — [Registro Seleccionado]`) y se expande o contrae con un clic.
- **Asociación Nativa de Archivos `.kvlt` en Windows**:
  - Registra automáticamente la extensión `.kvlt` en el sistema (`HKCU\Software\Classes\.kvlt`) con el icono oficial de **KVault Desktop**.
  - Al hacer **doble clic** sobre cualquier archivo `.kvlt` en el Explorador de Windows, se abre directamente en **KVault Desktop** listo para desbloquearse.
- **Autenticador 2FA TOTP (RFC 6238) Integrado**:
  - Soporta semillas Base32 (`JBSWY3DPEHPK3PXP`) y URIs `otpauth://totp/...`.
  - Muestra el código de 6 dígitos actualizado cada 30 segundos con barra de progreso y copia directa (`Ctrl + T`).
- **Motor Nativo de Auto-Type (`Ctrl + V` / `Ctrl + Shift + V`)**:
  - Cede el foco automáticamente a la ventana anterior activa del usuario (navegador, terminal SSH, cliente RDP) y escribe la secuencia de inicio de sesión sin pasar por el portapapeles.
  - Escapa de forma literal cualquier símbolo especial (`+`, `^`, `%`, `~`, `(`, `)`, `{`, `}`, `[`, `]`) para soportar contraseñas de alta complejidad.
- **Generador Criptográfico CSPRNG (Sin Sesgo de Módulo)**:
  - Genera contraseñas de 12 a 64 caracteres mediante muestreo por rechazo (*Rejection Sampling*) sobre `crypto.randomBytes`, calculando los bits de entropía en tiempo real.
- **Módulo Importador XML / CSV**:
  - Permite migrar bóvedas externas en formato `.xml` jerárquico (conservando grupos, subgrupos, notas y semillas TOTP) o archivos `.csv`.

---

## Controles Rápidos y Atajos de Teclado

### Acciones con el Ratón
- **Doble clic en archivo `.kvlt` (Explorador de Windows)**: Abre la bóveda en KVault Desktop.
- **Doble clic en celda `URL`**: Abre el enlace en el navegador predeterminado.
- **Doble clic en celda `Usuario`**: Copia el usuario al portapapeles (12s Auto-Wipe).
- **Doble clic en celda `Entropía`**: Copia la contraseña al portapapeles (12s Auto-Wipe).
- **Doble clic en celda `2FA`**: Copia el código TOTP de 6 dígitos.
- **Doble clic en celda `Título`**: Abre el editor del registro.
- **Clic derecho en cualquier fila**: Despliega el menú contextual completo de acciones.

### Mapa de Atajos de Teclado

| Atajo | Acción |
| :--- | :--- |
| **`Ctrl + V`** | **Auto-Type**: Cambia a la ventana anterior y escribe `{USERNAME} → {TAB} → {PASSWORD} → {ENTER}` |
| **`Ctrl + Shift + V`** | **Auto-Type Alternativo**: `{USERNAME} → {TAB} → {PASSWORD} → {TAB} → {SPACE}` |
| **`Ctrl + C`** | Copiar **Contraseña** (excluida de `Win + V`, purga selectiva en 12s) |
| **`Ctrl + B`** | Copiar **Usuario** |
| **`Ctrl + T`** | Copiar **Código 2FA TOTP** de 6 dígitos |
| **`Ctrl + U`** | **Abrir URL** en el navegador predeterminado |
| **`Ctrl + Shift + U`** | **Copiar URL** al portapapeles |
| **`Ctrl + Shift + X`** | **Purgar ahora** el secreto activo del portapapeles |
| **`Ctrl + I`** | Crear **Nueva Entrada** |
| **`Ctrl + K`** | **Duplicar** entrada seleccionada |
| **`Enter` / `F2`** | **Editar** entrada seleccionada |
| **`Supr` (`Delete`)** | **Eliminar** entrada seleccionada |
| **`↑` / `↓`** | Navegar entre registros de la tabla |
| **`Ctrl + F`** | Enfocar barra de filtrado instantáneo |
| **`Ctrl + S`** | Guardar contenedor `.kvlt` en disco |
| **`Ctrl + L`** | Purgar RAM (`Zeroize`) y **Bloquear Bóveda** |

---

## Estructura del Proyecto

```text
kvault-desktop/
├── assets/
│   ├── icon.ico                  # Icono multi-resolución (256px-16px) para la app y archivos .kvlt
│   └── icon.png                  # Icono PNG de alta resolución
├── scripts/
│   └── generate-icon.ps1         # Generador vectorial del icono oficial .ico/.png
├── src/
│   ├── main.js                   # Proceso principal Electron, aislamiento IPC, temas y sesión
│   ├── preload.js                # ContextBridge seguro (Sandbox + Context Isolation)
│   ├── core/
│   │   ├── vaultFormat.js        # Especificación y serializador AEAD del formato unificado .kvlt v2
│   │   ├── chacha20poly1305.js   # Implementación RFC 8439 ChaCha20-Poly1305 AEAD
│   │   ├── fido2Hardware.js      # Criptografía P-256 y Key Slot para llaves físicas FIDO2 / U2F
│   │   ├── win32WebAuthn.ps1     # Puente nativo P/Invoke contra webauthn.dll de Windows 10/11
│   │   ├── fileAssociation.js    # Asociación automática de extensión .kvlt e icono en Windows
│   │   ├── win32FileAssoc.ps1    # Registro HKCU\Software\Classes\.kvlt y SHChangeNotify
│   │   ├── protectedMemory.js    # Cifrado efímero en RAM y borrado determinista Zeroize
│   │   ├── totp.js               # Generador RFC 6238 TOTP y CSPRNG con cálculo de entropía
│   │   ├── autoType.js           # Motor de escritura automática y puente de portapapeles
│   │   └── win32Clipboard.ps1    # Integración Win32 user32.dll (Exclusión Win+V y ClearIfOwner)
│   ├── importer/
│   │   └── keepassImporter.js    # Importador de estructuras XML jerárquicas y CSV
│   └── ui/
│       ├── index.html            # Interfaz principal, paneles colapsables y modales
│       ├── styles.css            # Diseño utilitario de escritorio (Temas Oscuro, Claro y Auto OS)
│       └── renderer.js           # Controlador de vistas, temas, atajos, menú contextual y TOTP
└── test/
    └── test-vault.js             # Suite de pruebas criptográficas, AAD, FIDO2/U2F, memoria e importación
```

---

## Descarga, Instalación y Compilación

### Ejecutables Precompilados (Release v1.0.0)
Disponibles directamente en la sección [**Releases**](https://github.com/EVL87/kvault-desktop/releases/tag/v1.0.0):
- **`KVault-Desktop-Setup-1.0.0.exe`**: Instalador para Windows 10/11 x64 (crea accesos directos y asocia automáticamente los archivos `.kvlt` con el icono de la aplicación).
- **`KVault-Desktop-Portable-1.0.0.exe`**: Ejecutable portable autónomo de un solo archivo.

### Desarrollo y Compilación Desde Código Fuente

```powershell
cd kvault-desktop

# 1. Instalar dependencias
npm install

# 2. Ejecutar la suite de verificación criptográfica y de memoria (6/6 pruebas)
npm test

# 3. Iniciar KVault Desktop en modo desarrollo
npm start

# 4. Compilar instalador NSIS y ejecutable Portable (.exe) en dist/
npm run build:exe
```
