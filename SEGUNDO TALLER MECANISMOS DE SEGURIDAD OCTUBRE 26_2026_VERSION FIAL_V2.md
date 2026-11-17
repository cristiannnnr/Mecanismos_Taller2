**Universidad Distrital FJDC . Ingeniería de Sistemas. Octavio José Salcedo Parra. Fundamentos de redes de comunicaciones. GUÍA–TALLER DE REDES. Octubre 26/ 2026.** 

**Entrega: Noviembre 14 / 2026** 

# **GUÍA–TALLER No. 2** 

### **Mecanismos de seguridad para redes IEEE 802.3 con servidores TCP/IP** 

_Laboratorio académico, aislado y autorizado_ 

#### **_Parte I._** 

###### 1. Presentación y alcance 

La práctica estudia riesgos de disponibilidad, confidencialidad e integridad en una LAN Ethernet IEEE 802.3 que transporta IPv4/IPv6 y servicios TCP/IP. El trabajo se realiza exclusivamente en equipos propios o máquinas virtuales, con direcciones privadas, tráfico de prueba y autorización expresa. No se debe generar tráfico hacia Internet, redes institucionales en producción ni direcciones de terceros. 

## **2. Objetivos** 

- Reconocer indicadores de compromiso y comportamientos anómalos en tráfico TCP, UDP, ICMP, DNS, HTTP/HTTPS y mensajería. 

- Usar Wireshark y registros del sistema para correlacionar eventos, direcciones, puertos, marcas de tiempo y estados de conexión. 

- Evaluar controles preventivos y detectivos: firewall, segmentación, endurecimiento de servicios, TLS, limitación de tasa e IDS/SIEM. 

- Proponer el uso responsable de aprendizaje automático para priorizar alertas, sin delegar bloqueos automáticos críticos a un modelo no validado. 

- Documentar resultados reproducibles mediante capturas, filtros, registros, hashes y recomendaciones verificables. 

## **3. Resultados de aprendizaje** 

- Diferencia entre síntoma, indicador, hipótesis y evidencia confirmada. 

- Interpreta capturas de paquetes y registros sin confundir anomalías con prueba definitiva de ataque. 

- Relaciona cada caso con controles preventivos, detectivos, correctivos y de recuperación. 

- Entrega un informe técnico con hallazgos, limitaciones y un plan de mejora priorizado. 

## **4. Topología y reglas del laboratorio** 

Topología sugerida (ejemplo; se pueden usar direcciones privadas equivalentes): 

|**Elemento**|**Dirección / función**|**Recomendación**|
|---|---|---|
|**Switch Ethernet IEEE 802.3**|VLAN de laboratorio|Sin conexión a la red productiva|
|**Equipo analista**|192.168.50.10/24|Wireshark; acceso a logs|
|**Servidor web/pruebas**|192.168.50.20/24|HTTP de laboratorio o HTTPS|
|**Servidor DNS de laboratorio**|192.168.50.53/24|Resolver solo nombres de<br>prueba|
|**Servidor de mensajería**<br>**opcional**|192.168.50.30/24|XMPP en entorno aislado|
|**Gateway de laboratorio**|192.168.50.1/24|Sin reenvío hacia Internet;<br>filtrado habilitado|



Reglas obligatorias: 

- Usar exclusivamente equipos/VM bajo control del grupo y una VLAN o red virtual aislada. 

- Generar tráfico de prueba benigno o utilizar PCAP didácticos/sintéticos. Ejecutar DoS, exfiltración, spoofing controlados o ambientes aislados. 

- Sincronizar los relojes de los equipos y registrar fecha, hora, IP, puerto, herramienta y versión. 

- Anonimizar datos personales y credenciales; no capturar tráfico de usuarios ajenos al laboratorio. 

- Guardar una copia original de cada evidencia y calcular su hash SHA-256; analizar una copia de trabajo. 

## **5. Herramientas sugeridas** 

Wireshark; netstat y PowerShell en Windows; Visor de eventos; Windows Defender Firewall; Zeek y/o Suricata cuando estén disponibles; Wazuh o un SIEM equivalente; Python y scikit-learn para análisis de características agregadas. Utilice herramientas y versiones aprobadas por el docente. 

## **6. Casos críticos de trabajo** 

En cada caso, el equipo debe completar las tareas de observación y análisis, justificar los indicadores, proponer controles y adjuntar evidencia. Las actividades de ataque se sustituyen por análisis de PCAP, telemetría sintética o pruebas benignas autorizadas. 

##### **Caso 1. TCP SYN Flood: indisponibilidad y agotamiento de conexiones** 

**Situación.** Un servidor web de laboratorio responde lentamente o deja de aceptar nuevas conexiones. 

###### **Procedimiento:** 

- En una captura de tráfico previamente generada o una prueba de carga benigna autorizada, revisar el establecimiento TCP y contar SYN, SYN/ACK y ACK por ventana temporal. 

- En Windows, inspeccionar estados de conexión con `netstat -ano` y relacionar PID/servicio cuando proceda. 

- Comparar la tasa de intentos con una línea base normal; revisar registros del servidor y del firewall. 

###### **Indicadores que deben buscarse:** 

- Picos de SYN sin completar el handshake; incremento de conexiones pendientes; muchas fuentes o patrón temporal inusual. Un indicador aislado no confirma un ataque. 

###### **Mitigación / defensa:** 

- Mantener sistema y servicio actualizados; limitar exposición; aplicar protección SYN disponible en la plataforma; establecer límites de tasa en controles de red y escalar al administrador de infraestructura. 

- Validar que la mitigación no bloquee clientes legítimos. 

###### **Evidencias que se entregan:** 

- Gráfica temporal de SYN/ACK; tabla de conexiones; regla/alerta propuesta; comparación antes/después. 

###### **Preguntas de análisis:** 

- ¿Qué recursos mantiene el servidor durante el handshake TCP? ¿Qué falsos positivos pueden producir picos legítimos? 

##### **Caso 2. DNS tunneling: posible salida encubierta mediante UDP/53** 

**Situación.** Se observa tráfico DNS con consultas repetitivas o nombres de dominio inusualmente largos. 

**Procedimiento:** 

- Aplicar en Wireshark el filtro `udp.port == 53` y, cuando corresponda, `dns`. 

- Examinar longitud y entropía aproximada de etiquetas, frecuencia, volumen por cliente y dominios consultados. 

- Correlacionar con el resolver autorizado y registros DNS; usar únicamente dominios de prueba o PCAP de entrenamiento. 

###### **Indicadores que deben buscarse:** 

- Subdominios largos o de alta entropía, alta frecuencia, respuestas/tamaños atípicos y destinos no habituales; verificar explicaciones legítimas como telemetría o CDN. 

###### **Mitigación / defensa:** 

- Forzar el uso de resolvers autorizados; registrar consultas; aplicar filtrado DNS y políticas de salida; investigar el host origen antes de bloquear. 

###### **Evidencias que se entregan:** 

- Capturas filtradas, tabla por host/dominio, hipótesis y verificación con logs. 

###### **Preguntas de análisis:** 

- ¿Por qué el carácter sin conexión de UDP no significa que todo DNS sea malicioso? ¿Qué atributos ayudan a distinguir una anomalía? 

##### **Caso 3. Exposición de servicios HTTP, FTP y otros servicios heredados** 

**Situación.** El servidor presenta servicios abiertos que podrían estar innecesarios o débilmente configurados. 

###### **Procedimiento:** 

- Inventariar servicios y puertos en el servidor propio usando el inventario del sistema y una comprobación autorizada de alcance limitado. 

- Revisar registros de autenticación y eventos del sistema; documentar versión, necesidad operativa y propietario de cada servicio. 

- Comprobar si se utiliza cifrado y si las cuentas siguen el principio de mínimo privilegio. 

###### **Indicadores que deben buscarse:** 

- Servicios expuestos sin necesidad, software sin soporte, intentos de autenticación fallidos, uso de protocolos en texto claro o configuraciones por defecto. 

###### **Mitigación / defensa:** 

- Deshabilitar servicios no requeridos; preferir SFTP/SSH o HTTPS frente a protocolos en texto claro; MFA donde aplique; parcheo y cuentas de mínimo privilegio. 

###### **Evidencias que se entregan:** 

- Inventario de servicios, eventos relevantes, matriz riesgo/criticidad y plan de remediación. 

###### **Preguntas de análisis:** 

- ¿Cómo se prioriza un puerto abierto? ¿Qué diferencia hay entre exposición, vulnerabilidad y explotación? 

##### **Caso 4. Detección de anomalías con IA/ML en tráfico TCP/IP** 

**Situación.** El equipo debe proponer una defensa inteligente que identifique desviaciones frente al tráfico normal. 

###### **Procedimiento:** 

- Crear un conjunto de datos con PCAP didácticos o tráfico benigno de laboratorio y características agregadas: conexiones/minuto, bytes por flujo, duración, flags TCP y proporción petición/respuesta. 

- Separar datos de entrenamiento y evaluación por tiempo o sesión para evitar fuga de información. 

- Comparar una línea base estadística con un detector de anomalías; documentar precisión, falsos positivos y límites. 

###### **Indicadores que deben buscarse:** 

- Desviación sostenida respecto a la línea base; score de anomalía alto que debe investigarse junto con evidencia de red y logs. 

###### **Mitigación / defensa:** 

- Mantener revisión humana; monitorizar deriva del modelo; no usar la salida de un prototipo como única razón para bloquear; proteger los datos de entrenamiento. 

###### **Evidencias que se entregan:** 

- Notebook o script reproducible, definición de atributos, métricas, matriz de confusión si hay etiquetas y ejemplos anonimizados. 

###### **Preguntas de análisis:** 

- ¿Cómo afectan el desbalance de clases y los cambios legítimos de carga? ¿Qué métrica es más útil para el caso? 

##### **Caso 5. TCP: resets inesperados e indicios de inyección o desincronización** 

**Situación.** Aplicaciones reportan sesiones TCP que terminan abruptamente o se reinician de forma repetida. 

**Procedimiento:** 

- En una PCAP de laboratorio, filtrar `tcp.flags.reset == 1` y correlacionar marcas de tiempo, endpoints y sesiones. 

- Examinar si los RST coinciden con cierres legítimos, reinicios de servicio, firewall o pérdida de conectividad. 

- Correlacionar con registros de Zeek/Suricata y logs de aplicación, si están instalados. 

###### **Indicadores que deben buscarse:** 

- RST fuera de contexto, frecuencia inusual, sesiones truncadas o inconsistencias que requieren correlación; no inferir MITM solo por observar RST. 

###### **Mitigación / defensa:** 

- Usar TLS correctamente validado; segmentar la red; actualizar endpoints; activar detección IDS y revisar rutas/dispositivos intermedios. 

###### **Evidencias que se entregan:** 

- Tabla de flujos afectados, extractos de logs, tiempos y hash SHA-256 de la PCAP. 

###### **Preguntas de análisis:** 

- ¿Qué causas benignas generan RST? ¿Qué evidencia adicional haría más sólida la hipótesis de manipulación? 

##### **Caso 6. UDP: reflexión/amplificación DNS, NTP o SSDP** 

**Situación.** El servidor o gateway registra un volumen inusual de respuestas UDP, posiblemente desproporcionado respecto a las solicitudes. 

###### **Procedimiento:** 

- Examinar el volumen por protocolo, origen, destino y ventana temporal; distinguir tráfico esperado de respuestas no solicitadas. 

- Revisar la configuración de servicios propios y confirmar que no actúan como reflectores abiertos. 

- No generar tráfico de amplificación: usar PCAP de entrenamiento o contadores agregados simulados. 

###### **Indicadores que deben buscarse:** 

- Gran volumen de respuestas, asimetría petición/respuesta, puertos inesperados y destinos no relacionados con solicitudes observadas. 

###### **Mitigación / defensa:** 

- Deshabilitar servicios innecesarios; restringir consultas recursivas DNS; aplicar rate limiting y filtrado anti-spoofing en infraestructura administrada. 

###### **Evidencias que se entregan:** 

- Gráficas de paquetes/bytes por segundo, inventario de servicios y controles recomendados. 

###### **Preguntas de análisis:** 

- ¿Cómo se diferencia una ráfaga legítima de un patrón de reflexión? ¿Qué controles corresponden al servidor y cuáles al proveedor de red? 

##### **Caso 7. ICMP: escaneo, payloads atípicos y posible túnel** 

**Situación.** Se observa una tasa de ICMP mayor de lo habitual o paquetes con tamaños/patrones repetitivos. 

**Procedimiento:** 

- En Wireshark filtrar `icmp` y agrupar por IP origen/destino, tipo, código, longitud y tiempo. 

- Establecer una línea base de ping de diagnóstico legítimo y compararla con la captura analizada. 

- Usar PCAP sintético o didáctico para estudiar payloads; no transmitir información sensible por ICMP. 

###### **Indicadores que deben buscarse:** 

- Ráfagas de echo request/reply, longitudes inusuales, periodicidad repetitiva o volumen no explicado por tareas de diagnóstico. 

###### **Mitigación / defensa:** 

- Permitir solo los tipos ICMP necesarios para operación y diagnóstico; aplicar límites proporcionados; monitorizar sin bloquear indiscriminadamente mensajes requeridos por la red. 

###### **Evidencias que se entregan:** 

- Dashboard por IP, filtro aplicado, tabla de tamaños/frecuencias y propuesta de regla. 

###### **Preguntas de análisis:** 

- ¿Qué funciones legítimas cumple ICMP? ¿Qué impacto tendría bloquearlo completamente? 

##### **Caso 8. Escaneo de puertos y fingerprinting de servicios** 

**Situación.** Los logs muestran intentos secuenciales contra varios puertos o servicios no habituales. 

**Procedimiento:** 

- Analizar registros del firewall/IDS y una PCAP autorizada; contar destinos/puertos únicos por origen y periodo. 

- Correlacionar eventos de Zeek y Suricata, si están disponibles. 

- Elaborar una lista de exposición de los servicios propios, sin sondear redes ajenas. 

###### **Indicadores que deben buscarse:** 

- Conexiones a muchos puertos en poco tiempo, intentos repetidos a servicios inexistentes y consultas de banner/versiones no habituales. 

###### **Mitigación / defensa:** 

- Reducir superficie expuesta; filtrar por necesidad; actualizar servicios; alertar ante patrones repetidos y aplicar bloqueo temporal con revisión. 

###### **Evidencias que se entregan:** 

- Lista de indicadores, puertos/servicios expuestos, regla de detección y plan de endurecimiento. 

###### **Preguntas de análisis:** 

- ¿Qué limitaciones tiene atribuir un escaneo a una sola IP? ¿Cómo se reducen falsos positivos por monitoreo autorizado? 

##### **Caso 9. Priorización y correlación de alertas con IA y SIEM** 

**Situación.** El centro de monitoreo recibe múltiples alertas que deben agruparse y priorizarse. 

###### **Procedimiento:** 

- Normalizar eventos de firewall, servidor, Zeek/Suricata y sistema operativo; eliminar duplicados sin perder trazabilidad. 

- Definir características agregadas por host/ventana temporal y probar un detector de anomalías con datos controlados. 

- Usar un LLM únicamente para resumir alertas anonimizadas y sugerir triage; verificar toda recomendación contra evidencia. 

###### **Indicadores que deben buscarse:** 

- Alertas correlacionadas por host/tiempo, puntuación de riesgo explicable y señales convergentes en varias fuentes. 

###### **Mitigación / defensa:** 

- Revisión humana antes de acciones disruptivas; control de acceso a logs; evaluación de sesgo/deriva; registro de decisiones y posibilidad de reversión. 

###### **Evidencias que se entregan:** 

- Diagrama de pipeline, ejemplo de alerta enriquecida, criterios de prioridad y registro de validación humana. 

###### **Preguntas de análisis:** 

- ¿Cómo explicar una alerta a un analista? ¿Qué riesgo supone automatizar bloqueos basados solo en una puntuación? 

##### **Caso 10. Mensajería XMPP: interceptación y errores de TLS** 

**Situación.** Se investiga si la comunicación entre clientes y servidor de mensajería está correctamente protegida. 

**Procedimiento:** 

- En un servidor XMPP de laboratorio (por ejemplo, Openfire o ejabberd), revisar configuración TLS, certificados, nombres, vigencia y cadena de confianza. 

- Capturar metadatos de conexión en una prueba autorizada y verificar que el contenido de una sesión cifrada no se trate como texto legible. 

- Revisar logs del servidor en busca de errores de negociación, certificados inválidos o conexiones inesperadas. 

**Indicadores que deben buscarse:** 

- Certificados vencidos/no confiables, negociación insegura, servicios de administración expuestos o patrones de conexión que no coinciden con el uso esperado. 

###### **Mitigación / defensa:** 

- Exigir TLS robusto y validación de certificados; limitar interfaces administrativas; mantener el servidor actualizado; aplicar E2EE cuando el modelo de amenaza lo requiera. 

###### **Evidencias que se entregan:** 

- Checklist TLS, eventos anonimizados, evidencia de configuración y plan de corrección. 

###### **Preguntas de análisis:** 

- ¿Qué protege TLS y qué no protege? ¿En qué se diferencia el cifrado de transporte del cifrado de extremo a extremo? 

## **7. Formato mínimo de registro por hallazgo** 

|**Campo **|**Qué registrar**|
|---|---|
|**Identificador**|Caso, número de evidencia y nombre del<br>analista.|
|**Fecha/hora**|Marca temporal y zona horaria; sincronización<br>conocida.|
|**Origen/destino**|IP, MAC cuando sea pertinente, puertos y<br>protocolo; anonimizar si aplica.|
|**Observación**|Hecho directamente observado, sin<br>conclusiones prematuras.|
|**Hipótesis**|Explicación posible y alternativas benignas<br>consideradas.|
|**Validación**|PCAP/log consultado, filtro, comandos de<br>inspección y resultado.|
|**Severidad**|Impacto, probabilidad y justificación.|
|**Acción**|Medida propuesta, responsable, riesgo de falsos<br>positivos y verificación.|
|**Integridad**|Nombre de archivo, tamaño y hash SHA-256 de<br>la evidencia original.|



##### **8. Entregables** 

- Informe técnico por equipo, con resumen ejecutivo y alcance del laboratorio. 

- Diez fichas de caso con indicadores, análisis, hipótesis alternativas y medidas de defensa. 

- Capturas de pantalla legibles y PCAP didácticas/sintéticas cuando corresponda, con hash SHA256. 

- Reglas de detección propuestas y justificadas; no se exige activar bloqueos automáticos en producción. 

- Conclusiones sobre límites de la evidencia y oportunidades de mejora. 

#### **_Parte II._ Programación.  Utilizando técnicas, aplicaciones e Inteligencia Artificial.** 

**Crear una** app, programa o bot para rastrear (ubicar) números telefónicos **de servicios de mensajería instantánea como** WhatsApp **,** Telegram **, o directamente la** ubicación geográfica de un celular. **Explicación, requerimientos y aspectos técnicos para desarrollar un sistema (app, programa o bot) que:** 

**Explicación. Rastree la ubicación geográfica de un número telefónico** asociado a: WhatsApp (limitado, indirecto) , Telegram (con bots) , Celular directamente (usando GPS) 

##### **Muestre en tiempo real o por intervalos** la ubicación del usuario. 

##### **4.1. Requisitos Funcionales** 

##### **Requisito** 

##### **Descripción** 

|Registro por número<br>telefónico|El sistema debe registrar y vincular dispositivos a través<br>del número telefónico.|
|---|---|
|Solicitud y captura de<br>ubicación|Permitir al usuario objetivo enviar su ubicación actual o<br>automática.|
|Actualización periódica|<sup>Capturar la ubicación del dispositivo cada intervalo</sup><br>definido (ej. cada 10 minutos).|
|Visualización en mapa|Mostrar ubicación en un mapa integrado (Google Maps,<br>OpenStreetMap, etc.).|
|Alertas (opcional)|Alertar si el dispositivo entra o sale de una zona geográfica<br>(geofencing).|
|Historial de ubicaciones|Guardar y consultar ubicaciones pasadas por fecha/hora.|
|Acceso seguro|Autenticación del usuario|



##### **4.3 Requisitos Técnicos** 

##### 4.3.1. Aplicación móvil (necesaria para ubicación directa) 

- **Android/iOS app** instalada en el dispositivo objetivo. 

- Solicitud de permisos de **GPS/localización** . 

- Envío periódico de coordenadas al servidor (backend). 

- Vinculación con número telefónico (SMS o código de verificación). 

#### **4.3.2. Bot en Telegram (opcional)** 

- El bot puede solicitar ubicación manual mediante botones. 

- **No puede rastrear automáticamente** sin que el usuario lo envíe. 

- • Requiere que el usuario inicie el chat y lo autorice. 

##### **4.3.3. Backend (servidor)** 

- Lenguaje: Python, Node.js, PHP o similar. 

- API REST para enviar/recibir ubicación. 

- Base de datos: PostgreSQL, MongoDB o Firebase. 

- • Sistema de autenticación (por número y token). 

##### **4.3.4 Mapa y visualización** 

   - API de Google Maps, Mapbox o Leaflet.js para mostrar las ubicaciones. 

   - Soporte para geocodificación inversa (coordenadas → dirección). 

- **4.4 Características opcionales avanzadas** 

- 4.4.1 Geofencing personalizado (notificaciones por zona) 

- 4.4.2 Ahorro de batería mediante activación programada 

- 4.4.3 Múltiples dispositivos vinculados (familia, empleados) 

- 4.4.4 Interfaz web o panel administrativo 

- 4.4.5 Estadísticas de movimiento o recorridos 

**Nota Importante:** El taller No. 2, a desarrollar (resolver), no se está pidiendo (solicitando) ingeniera(o), que vulnere, ataque o hackea ninguno de los escenarios domésticos o empresariales a los cuales Usted pueda tener acceso. El ejercicio es carácter académico. Los participantes deben actuar como hackers éticos, sin causar daño intencional a sistemas (redes de comunicaciones) y personas. No se permite el uso de técnicas que comprometan la integridad de sistemas (redes de comunicaciones y servidores TCP/IP) reales sin permiso o autorización expresa de los propietarios de los escenarios en cuestión. 

