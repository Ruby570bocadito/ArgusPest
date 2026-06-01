# ARGOS gRPC Protocol — Referencia de la API

La comunicación entre el **Director (C2)** y los **Agentes (Cells / Stagers)** se realiza exclusivamente a través de gRPC utilizando Protocol Buffers, encapsulados opcionalmente en tráfico Chameleon (WebSockets / TLS falso).

Si deseas programar un nuevo agente (ej. en Rust o C++) para Argos, debes implementar los siguientes servicios definidos en `shared/proto/argos.proto`.

## 1. Servicio: `AgentC2`

Este es el servicio expuesto por el servidor (Director) al que los agentes se conectan.

### `rpc Register (AgentInfo) returns (RegisterAck)`
- **Uso:** Primera llamada que hace el agente para obtener un `mission_id` y su intervalo de beaconing.
- **Payload:** `AgentInfo` debe contener OS, Arch, Hostname, IP y un ID único generado localmente.
- **Respuesta:** Devuelve un booleano `success` y el `beacon_interval_sec` que el agente debe respetar.

### `rpc Beacon (stream AgentEvent) returns (stream DirectorCommand)`
- **Uso:** El canal principal (bidireccional) de comunicación.
- **Subida (AgentEvent):** El agente envía eventos como `HEARTBEAT`, `SCAN_RESULT`, `EXPLOIT_RESULT`, `DEFENSE_ALERT` o `FLAG_CAPTURED`.
- **Bajada (DirectorCommand):** El servidor envía comandos empaquetados (`SCAN`, `EXPLOIT`, `PERSIST`, `PIVOT`, `SLEEP`, `SELF_DESTRUCT`).

## 2. Modelos de Datos (AgentEvent)

### Escaneo de Red
Cuando recibas un comando `CommandType_SCAN`, debes ejecutar un portscan y responder con un `SCAN_RESULT`:
```protobuf
message ScanResult {
    string target_ip = 1;
    repeated ServiceInfo services = 2; // Array de puertos abiertos con banner/versión
}
```

### Resultados de Explotación / Movimiento Lateral
Al ejecutar una táctica, reportas el éxito mediante `EXPLOIT_RESULT`:
```protobuf
message ExploitResult {
    string cve_or_technique = 1;
    bool success = 2;
    string output = 3;  // Salida del comando, dumps, etc.
    string error = 4;   // Razón de fallo si no hubo éxito
}
```

## 3. Implementación del Heartbeat

Es responsabilidad del agente enviar latidos periódicos al flujo del Beacon basándose en el `beacon_interval_sec`. Si el servidor no recibe un latido en un tiempo prolongado, marcará al agente como `Dead`.

```protobuf
message Heartbeat {
    float cpu_usage = 1;
    float mem_usage = 2;
}
```
