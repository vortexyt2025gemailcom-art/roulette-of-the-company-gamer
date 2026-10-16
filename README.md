# 🎡 Ruleta

Ruleta de nombres con tienda de skins, monedas, cuentas, regalos y radio.
Es una página (`index.html`) más un servidor pequeño (`/api`) hecho con una función de Netlify.

## Archivos

| Archivo | Qué hace |
|---|---|
| `index.html` | La app completa: lo que ve la gente |
| `netlify/functions/api.mjs` | El servidor `/api`: cuentas, monedas, tienda, regalos y códigos |
| `netlify.toml` | Configuración de Netlify |
| `package.json` | Instala `@netlify/blobs`, donde se guardan los datos |

La carpeta `netlify/functions/` tiene que llamarse exactamente así.

## Publicar en Netlify

1. Sube estos archivos a GitHub (con la carpeta `netlify/functions/`).
2. En Netlify crea un sitio nuevo desde GitHub (*Import an existing project*) y elige este repositorio. No pongas comando de build: lo demás ya viene en `netlify.toml`.
3. En **Site configuration → Environment variables** crea `OWNER_KEY` con tu código de dueño (mínimo 6 caracteres) y haz **Trigger deploy** otra vez.

## Modo dueño

Toca la esquina inferior derecha de la pantalla (hay un botón invisible), escribe el `OWNER_KEY` y se activa.
Con eso puedes agarrar monedas gratis y crear códigos de regalo de un solo uso.

## Cómo funciona

- Los datos se guardan en Netlify Blobs (store `ruleta`): `u/<nombre>` cuenta, monedas y compras · `d/<nombre>` ajustes y lista de la ruleta · `c/<código>` códigos de regalo.
- Las monedas y las compras las controla solo el servidor: el celular no puede ponerse monedas.
- Las contraseñas se guardan con scrypt, nunca en texto.
- Se ganan 50 monedas por minuto (máximo). Las cuentas nuevas empiezan con 500.
- 5 contraseñas malas bloquean la cuenta 10 minutos.

## Si cambias precios

Los precios de la tienda están en dos lugares: en `index.html` y arriba de `netlify/functions/api.mjs` (listas `WS`, `BG` y `DC`).
Si cambias o agregas una skin, hazlo en los dos; si no, el servidor cobra el precio viejo o dice que el artículo no existe.

## Límites a tener en cuenta

- La música y el anuncio que sube el dueño se guardan en el navegador de ese dispositivo (IndexedDB), no en el servidor: los demás usuarios no los ven.
- Netlify Blobs no es una base de datos transaccional. Para uso normal funciona bien; si la app crece mucho conviene pasar a una base de datos de verdad.
