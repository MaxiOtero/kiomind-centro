# KioMind Centro

Aplicación web instalable (PWA) para el dueño de KioMind: emite licencias por
equipo, lleva la lista de kioscos y guarda copias de seguridad cifradas.
Corre 100 % en el celular o la PC; no hay servidor ni cuenta.

## Publicarla en GitHub Pages (gratis)

1. En GitHub creá un repositorio nuevo, por ejemplo `kiomind-centro` (puede ser
   público: no contiene nada secreto, la llave privada vive solo en tu celular).
2. Subí el contenido de esta carpeta `centro/` a la raíz del repositorio.
3. En el repositorio: **Settings → Pages → Build and deployment → Source:
   Deploy from a branch**, branch `main`, carpeta `/ (root)`. Guardar.
4. En un minuto queda en `https://<tu-usuario>.github.io/kiomind-centro/`.

Desde tu PC de programación, con git ya instalado:

```bash
cd centro
git init
git add .
git commit -m "KioMind Centro"
git branch -M main
git remote add origin https://github.com/<tu-usuario>/kiomind-centro.git
git push -u origin main
```

Para actualizar la app más adelante: cambiá los archivos, `git commit` y
`git push`. Si cambiás algo, subí también el número `VERSION` en `sw.js` para
que los celulares tomen la versión nueva.

## Instalarla en el celular

- **Android (Chrome):** abrí la dirección, menú ⋮ → *Agregar a pantalla de
  inicio* / *Instalar app*.
- **iPhone (Safari):** abrí la dirección, botón Compartir → *Agregar a inicio*.

La primera vez pide crear una contraseña y genera la llave. Inmediatamente
después hacé la **copia de seguridad** (archivo `.kmc`) y guardala en Google
Drive o mail.

## Conectar con KioMind (una sola vez)

En Centro → **Ajustes → Copiar clave pública** y en la PC de programación:

```bash
npm run centro:clave -- <clave pública>
```

A partir de ahí todo instalador que generes con `npm run release:win` acepta
las licencias que emitas.

## Probarla en la PC

```bash
npm run centro:dev
```

y abrí `http://localhost:5178/`.

## Archivos

- `index.html`, `app.js`, `styles.css`: la app.
- `sw.js`, `manifest.webmanifest`, `icons/`: instalación y modo sin conexión.
- `vendor/nacl-fast.min.js` (TweetNaCl, firma Ed25519) y `vendor/jsQR.js`
  (lector de QR con la cámara).
