# Cyber Win: puesta en marcha

La aplicación conserva sus páginas HTML, pero las cuentas, los perfiles, los temas, los avisos, los creadores, los torneos, las inscripciones, las propuestas, los reportes, las amistades, los mensajes y los ajustes públicos se comparten mediante una API Node/Express y PostgreSQL. Las contraseñas se gestionan en Firebase Authentication; el servidor verifica los ID tokens de Firebase antes de acceder a datos privados.

## Requisitos

- Node.js 20 o posterior
- PostgreSQL 14 o posterior
- Un proyecto Firebase con el proveedor **Email/Password** habilitado
- Credenciales de Firebase Admin mediante Application Default Credentials
- Para retransmisión propia: una cuenta de Mux y sus credenciales de API/webhook

## Configuración local

1. Crea una base de datos PostgreSQL para Cyber Win.
2. Copia `.env.example` como `.env` y configura `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` y `DB_PASSWORD`; también puedes usar `DATABASE_URL`. Configura `FIREBASE_PROJECT_ID`. Activa `DATABASE_SSL=true` solo si tu proveedor SQL exige TLS. Para activar retransmisiones, configura `MUX_TOKEN_ID`, `MUX_TOKEN_SECRET` y `MUX_WEBHOOK_SECRET`; el resto de la aplicación puede arrancar sin Mux.
3. Proporciona credenciales de Firebase Admin con Application Default Credentials. Para desarrollo local puedes definir `GOOGLE_APPLICATION_CREDENTIALS` apuntando a un archivo de cuenta de servicio guardado fuera del repositorio. **No subas ese archivo ni `.env` al control de versiones.**
4. Copia los valores de la app web de Firebase Console a `firebase-config.js`. Esa configuración web es pública; no pegues una clave privada de servicio en ese archivo.
5. En Firebase Console, habilita Email/Password y agrega el dominio que usarás en **Authorized domains**.
6. Ejecuta `npm install`, luego `npm run migrate` y finalmente `npm start`.
7. Abre `http://localhost:3000/` para usuarios o `http://localhost:3000/admin` para administración. No abras los HTML con `file://`: Firebase modules y la API necesitan el servidor HTTP.

## Primer administrador

Registra primero la cuenta por la página de usuarios para que su UID se guarde en SQL. Después, usando una conexión segura a PostgreSQL, promueve explícitamente ese correo:

```sql
UPDATE users SET role = 'admin' WHERE email = 'admin@tu-dominio.com';
```

El rol se obtiene de PostgreSQL en cada solicitud administrativa; no se confía en un rol enviado por el navegador ni en claims editables por el usuario.

## API inicial

- `GET /api/health`: verifica conectividad con PostgreSQL.
- `GET /api/public/state`: torneos y ajustes públicos compartidos.
- `GET /api/admin/state` y `PUT /api/admin/state/:key`: lectura y edición administrativa del estado compartido.
- `POST /api/public/events/:id/registrations`: inscripción autenticada de un equipo.
- `POST /api/public/state/proposals`, `/bugs` y `/creator-applications`: enviar propuestas, reportes y postulaciones autenticadas.
- `GET /api/me` y `PUT /api/me`: consultar y actualizar el perfil de la cuenta autenticada.
- `GET /api/community/users?search=...`: buscar jugadores por nickname.
- `GET /api/friends`, `POST /api/friends/requests` y `POST /api/friends/requests/:id/respond`: consultar, enviar, aceptar o rechazar solicitudes; el listado incluye mensajes sin leer.
- `GET/POST /api/friends/:userId/messages`: consultar y enviar mensajes privados entre amigos aceptados.
- `GET /api/announcements`: avisos activos públicos.
- `GET/POST /api/admin/announcements` y `DELETE /api/admin/announcements/:id`: gestión administrativa de avisos.
- `GET /api/creators`, `POST /api/admin/creators` y `DELETE /api/admin/creators/:id`: catálogo y gestión de creadores/directos.
- `PATCH /api/admin/creators/:id/live`: marcar si un creador está transmitiendo; requiere un enlace live configurado.
- `GET /api/admin/users`: lista protegida de usuarios para administración.
- `POST /api/creator-applications`: enviar una postulación autenticada que aparece en la cola administrativa.
- `GET /api/admin/creator-applications` y `POST /api/admin/creator-applications/:id/review`: revisar postulaciones; aprobar crea/vincula el perfil de creador y asigna el rol `creator`.
- `PATCH /api/admin/users/:id/role`: asignar o retirar el rol de creador desde el panel de presencia; no permite cambiar cuentas administradoras.
- `GET /api/admin/monitoring`: métricas del proceso Node, sistema operativo, respuesta PostgreSQL y presencia autenticada de usuarios.
- `GET /api/creators/featured`: perfiles destacados y enlaces sociales públicos; `PUT /api/admin/creators/:id/profile` edita el perfil y vincula la cuenta creadora.
- `GET /api/creator/stream`, `POST /api/creator/stream`, `POST /api/creator/stream/reset-key`: panel, canal RTMP y renovación de clave para cuentas creadoras autorizadas.
- `GET /api/streams/live` y `GET /api/streams/videos`: directos y grabaciones listas para reproducción.
- `GET /api/admin/stream-assets` y `DELETE /api/admin/stream-assets/:id`: listado y eliminación definitiva de grabaciones en Mux.
- `POST /api/webhooks/mux`: actualiza el estado de los directos y las grabaciones; registra esta URL en Mux con el secreto de firma configurado.

### Retransmisión con OBS / Mux

El administrador crea o aprueba al creador y, en **Creadores y lives**, vincula su cuenta de Cyber Win. La persona vinculada verá **Mi streaming**, donde puede generar un canal y copiar a OBS la URL RTMP y la clave de transmisión. La clave se guarda cifrada en PostgreSQL; `MUX_TOKEN_SECRET` debe mantenerse estable mientras existan canales guardados, ya que cambiarlo impide descifrar las claves existentes.

En Mux configura el webhook `https://<dominio>/api/webhooks/mux` para eventos de live stream (`video.live_stream.active`, `video.live_stream.idle`) y de activos (`video.asset.created`, `video.asset.updated`, `video.asset.ready`, `video.asset.errored`, `video.asset.deleted`), y copia el signing secret en `MUX_WEBHOOK_SECRET`. El panel público reproduce lives y grabaciones con Mux Player. La eliminación administrativa borra el activo de Mux y de la base de datos.

El almacenamiento, el ancho de banda y la retención se facturan y administran en Mux; no se establece aquí una cuota ni una política automática de retención. Define límites y costos en Mux antes de abrir el streaming a producción.

Al cambiar un evento a **EN JUEGO**, el sistema genera una sola vez un bracket aleatorio (incluyendo byes cuando hagan falta) o una posición aleatoria inicial de liga; los puntos ordenan la tabla y el sorteo resuelve empates.

Los avatares se optimizan en el navegador a JPEG de hasta 300 KB y 512×512 px; los banners, a JPEG de hasta 700 KB y 1600×600 px. Las imágenes se almacenan en PostgreSQL junto con el perfil. El servidor valida el formato, el tamaño y los colores antes de guardar los cambios.

El chatbot es un asistente guiado de preguntas frecuentes que funciona en el navegador, usa información visible de los torneos y no transmite mensajes a modelos externos. Los mensajes directos se actualizan periódicamente mientras el chat está abierto.

La migración `002_shared_application_state.sql` crea el almacenamiento compartido de torneos, inscripciones, propuestas, reportes, postulaciones antiguas y ajustes. La migración `003_user_community.sql` añade personalización visual, amistades, mensajes y estado de directos. La migración `004_monitoring_collaborators_streams.sql` añade presencia, perfiles sociales y los canales/grabaciones Mux. La migración `005_creator_applications_and_chat.sql` convierte postulaciones pendientes existentes a registros revisables, habilita el rol `creator` y añade recibos de lectura al chat. `npm run migrate` aplica en orden todas las migraciones SQL pendientes o idempotentes.

La sección **Información de este navegador** muestra datos del equipo que abre la página; el monitoreo del servidor y las cuentas online/offline procede de métricas reales del proceso Node y PostgreSQL. La presencia se considera online cuando existe un heartbeat autenticado de los últimos 90 segundos. El chat actualiza la lista de conversaciones cada 5 segundos, enseña mensajes sin leer y marca como leído al abrir el chat. El asistente NOVA usa un personaje original 2D y efectos de luz CSS; no descarga imágenes de personajes ni requiere o activa ray tracing de GPU.
