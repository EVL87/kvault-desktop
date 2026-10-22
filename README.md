# KVault Desktop

**KVault Desktop** es un gestor de credenciales y secretos de escritorio de alta densidad para entornos técnicos y de seguridad (**SecOps / DevSecOps**). Utiliza un formato de contenedor binario autenticado propio (**`.kvlt`**), aislamiento criptográfico de secretos en memoria (**`ProtectedMemory`**), generador **2FA TOTP (RFC 6238)** integrado, motor nativo de **Auto-Type** y protección contra capturas de pantalla a nivel de ventana.

---

## ¿Qué es y cómo funciona?

A diferencia de los gestores basados en contenedores XML pesados o aplicaciones web empaquetadas que mantienen contraseñas como cadenas de texto plano inmutables en memoria, **KVault Desktop** opera bajo cuatro pilares técnicos:

### 1. Contenedor Binario Autenticado (`.kvlt` v1)
Cada bóveda se almacena en un archivo binario compacto con extensión `.kvlt`:
- **Cabecera Binaria Autenticada (AAD)**: Los primeros **58 bytes** de la cabecera (firma mágica `0x4B564C54` `"KVLT"`, versión, identificador de primitiva AEAD, parámetros KDF `N, r, p`, Salt de 256 bits y Nonce de 96 bits) se inyectan como **Additional Authenticated Data (AAD)** dentro del cifrado autenticado. Si se altera un solo bit de la cabecera en disco, la verificación del tag criptográfico (128 bits) aborta inmediatamente antes de descomprimir o procesar el contenido.
- **Doble Primitiva AEAD Seleccionable**:
  - `0x01` — **ChaCha20-Poly1305 (RFC 8439)**: Cifrado de flujo de 20 rondas autenticado con MAC Poly1305 sobre $GF(2^{130}-5)$.
  - `0x02` — **AES-256-GCM (NIST SP 800-38D)**: Cifrado por bloques acelerado por hardware (AES-NI) con autenticación Galois/Counter Mode.
- **Derivación de Clave Compuesta (Scrypt + KeyFile)**: Combina la Contraseña Maestra con un archivo llave opcional (**KeyFile**) mediante `SHA-512` y deriva la clave de 256 bits usando **Scrypt** de alta memoria (`N=16384, r=8, p=1`).
- **Persistencia Transaccional Atómica**: Al guardar cambios, escribe primero en un archivo temporal (`.tmp.<pid>`), fuerza el volcado físico de buffers al disco mediante `fsync` y ejecuta un renombrado atómico (`rename`), evitando corrupción de la bóveda ante cierres bruscos o cortes de energía.

```
Estructura binaria de 74 bytes de cabecera + Payload AEAD (.kvlt):
+-------------------+-------------------+-------------------+-------------------+
|  0..3 (4 bytes)   |   4 (1 byte)      |   5 (1 byte)      |  6..13 (8 bytes)  |
|  Magic: "KVLT"    |   Versión: 0x01   | Cipher: 0x01/0x02 | Scrypt (N, r, p)  |
+-------------------+-------------------+-------------------+-------------------+
|                         14..45 (32 bytes / 256 bits)                          |
|                         Salt Criptográfico Aleatorio                          |
+---------------------------------------+---------------------------------------+
|       46..57 (12 bytes / 96b)         |       58..73 (16 bytes / 128b)        |
|           Nonce / IV AEAD             |      Auth Tag (Poly1305 / GCM)        |
+---------------------------------------+---------------------------------------+
|                              74..N (Longitud variable)                        |
|                  Payload JSON comprimido (GZip L9) + Cifrado AEAD             |
+-------------------------------------------------------------------------------+
|<--- Bytes 0..57 protegidos con AAD --->|
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

### 5. Autenticación con Llaves Físicas por Hardware FIDO2 / U2F (100% Configurable)
- Integración nativa con `webauthn.dll` de Windows 10/11 para llaves físicas externas por USB-C o NFC:
  - **Yubico Security Key C NFC** (FIDO2 CTAP2 / FIDO U2F)
  - **Flipper Zero** (Modo `Apps → USB → U2F` CTAP1)
  - **YubiKey Serie 5 / SoloKeys / Nitrokey**
- **3 Modos de Operación (nunca obligatorio)**:
  1. **Modo 1 — Solo Contraseña Maestra (Por defecto)**: Uso tradicional sin llave física.
  2. **Modo 2 — Desbloqueo Rápido con Llave Física (1-Toque Passwordless)**: Desbloquea la bóveda con un solo toque físico en la Yubico Security Key o presionando `OK` en el Flipper Zero (verificando matemáticamente la firma **ECDSA P-256** del dispositivo y desencapsulando el Key Slot protegido con ChaCha20-Poly1305 + DPAPI), manteniendo la contraseña maestra como respaldo de emergencia.
  3. **Modo 3 — Doble Factor Estricto (Contraseña Maestra + Llave Física FIDO2/U2F)**: Combina criptográficamente (`HMAC-SHA256`) la Contraseña Maestra con un factor de 256 bits almacenado en el Key Slot de la llave física, exigiendo ambos factores para poder derivar la clave de `.kvlt`.

---

## Opciones y Funcionalidades Principales

- **Interfaz Utilitaria de 3 Paneles**:
  1. **Panel Izquierdo**: Árbol de grupos y subgrupos + panel de **Auditoría de Seguridad** en vivo (total de registros, entropía promedio en bits, contador de claves débiles y registros con 2FA activo).
  2. **Panel Central (DataGrid)**: Tabla de alta densidad con búsqueda instantánea (`Ctrl + F`), indicadores de 2FA, nivel de entropía y acciones directas por celda con doble clic.
  3. **Panel Derecho (Inspector Técnico)**: Visualización del tamaño del sobre cifrado en `ProtectedMemory`, revelación bajo demanda, copia rápida, notas técnicas, etiquetas y widget 2FA en tiempo real.
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
- **Doble clic en celda `URL`**: Abre el enlace en el navegador predeterminado.
- **Doble clic en celda `Usuario`**: Copia el usuario al portapapeles (12s Auto-Wipe).
- **Doble clic en celda `Entropía`**: Copia la contraseña al portapapeles (12s Auto-Wipe).
- **Doble clic en celda `2FA`**: Copia el código TOTP de 6 dígitos.
- **Doble clic en celda `Título`**: Abre el editor del registro.
- **Clic derecho en cualquier fila o en el Inspector**: Despliega el menú contextual completo de acciones.

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
├── package.json
├── src/
│   ├── main.js                   # Proceso principal Electron, aislamiento IPC y gestión de sesión
│   ├── preload.js                # ContextBridge seguro (Sandbox + Context Isolation)
│   ├── core/
│   │   ├── vaultFormat.js        # Especificación y serializador AEAD del formato binario .kvlt
│   │   ├── chacha20poly1305.js   # Implementación RFC 8439 ChaCha20-Poly1305 AEAD
│   │   ├── protectedMemory.js    # Cifrado efímero en RAM y borrado determinista Zeroize
│   │   ├── totp.js               # Generador RFC 6238 TOTP y CSPRNG con cálculo de entropía
│   │   ├── autoType.js           # Motor de escritura automática y puente de portapapeles
│   │   └── win32Clipboard.ps1    # Integración Win32 user32.dll (Exclusión Win+V y ClearIfOwner)
│   ├── importer/
│   │   └── keepassImporter.js    # Importador de estructuras XML jerárquicas y CSV
│   └── ui/
│       ├── index.html            # Interfaz de 3 paneles y estación de desbloqueo
│       ├── styles.css            # Diseño utilitario de escritorio de alta densidad
│       └── renderer.js           # Controlador de vistas, atajos, menú contextual y TOTP
└── test/
    └── test-vault.js             # Suite de pruebas criptográficas, AAD, memoria e importación
```

---

## Instalación y Uso

### Requisitos
- **Windows 10 / 11 (x64)**
- **Node.js 20+**

### Comandos

```powershell
cd kvault-desktop

# 1. Instalar dependencias
npm install

# 2. Ejecutar la suite de verificación criptográfica y de memoria
npm test

# 3. Iniciar KVault Desktop
npm start
```
