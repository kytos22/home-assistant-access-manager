# Integración con ESPHome Fingerprint Access Reader

Este add-on se integra con el firmware [ESPHome Fingerprint Access Reader](https://github.com/kytos22/esphome-fingerprint-access-reader) a través de entidades que Home Assistant descubre desde ESPHome. No hay conexión directa por IP ni secretos compartidos entre ambos proyectos.

## Configuración

1. Instala y adopta el firmware en Home Assistant.
2. Crea un lector de tipo **Fingerprint** en Access Manager.
3. Asigna las entidades del lector: evento de acceso, evento de gestión, registro de nombres y controles de enrolamiento/borrado.
4. Asocia el lector a una puerta y registra usuarios y huellas desde Access Manager.

## Contrato de eventos

El firmware publica en la entidad de evento de acceso:

```text
matched|<sequence>|<fingerprint id>|<confidence>|<requested action>
local_action|<sequence>|lock
```

`requested action` solo puede ser `default`, `open`, `unlock` o `lock`. Las acciones locales de la pantalla solo pueden solicitar `lock`. Access Manager comprueba la relación lector-puerta, las capacidades de la entidad de puerta y la asociación de la huella antes de ejecutar una acción.

Para mostrar el nombre localmente, el add-on escribe en la entidad de registro:

```text
set|<id>|<person name>|<finger key>
delete|<id>
```

Los cambios incompatibles en esos nombres de entidades o en estos formatos requieren una versión coordinada de ambos proyectos.
