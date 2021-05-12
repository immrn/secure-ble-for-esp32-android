# secure-ble-for-esp32-android
1. [Prerequisites](#1-Prerequisites)
2. [Setup](#2-Setup)
3. [Build](#3-Build)
4. [Application Details](#4-Application-Details)
5. [Links and Examples to Get Started](#5-Links-and-Examples-to-Get-Started)
6. [Continuation](#6-Continuation)

**Follow the [Setup](#2-Setup) section before building the projects for the first time!**

## 1. Prerequisites

- Microcontroller: [SBC-NodeMCU ESP32](https://joy-it.net/en/products/SBC-NodeMCU-ESP32)
- Android device: Android 6.0 or higher <!-- TODO update version -->

- ESP-IDF: follow the [Get-Started-Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
	- to follow this README it's recommended to [install the software manually](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
	- after installing you should [build mbedtls](https://tls.mbed.org/kb/compiling-and-building/how-do-i-build-compile-mbedtls) in `esp/esp-idf/components/mbedtls/mbedtls/`, this is necessary to run certificate and key generation later
	<!--	- mbedtls: download [here](https://tls.mbed.org/download) or install via a package manager (Ubuntu: `$ sudo apt install libmbedtls-dev`) -->
- [Android Studio](https://developer.android.com/studio)



## 2. Setup

To use these projects you need to create a subscription payload. Have a look at  

In `l2cap_client/main/main.c` change `peer_bt_addr` to the address the client shall connect to.
<!-- TODO for Android project too -->

You have to generate the certificates for the client and server application:
- **if using Linux/MacOS**:
	- in `secure-ble-for-esp32-android/` run the following (for more information look into `gen_cert_chain.sh`)
		```
		$ chmod +x ./gen_cert_chain.sh
		$ ./gen_cert_chain.sh PATH/TO/ESP/DIRECTORY
		```
- **else**:
	<details><summary>Click here</summary>
	<p>

	- make a dir `certs/`, go into `certs/`
	- set alias for "mbedtls_gen_key" to path/to/.../esp/esp-idf/components/mbedtls/mbedtls/programs/pkey/gen_key
	- set alias for "mbedtls_cert_write" to path/to/.../esp/esp-idf/components/mbedtls/mbedtls/programs/x509/cert_write
	- maybe adjust the following section and run it:
		```bash
		# 1. CA-Root:
		mbedtls_gen_key type=rsa rsa_keysize=4096 filename=ca.key format=pem
		mbedtls_cert_write selfsign=1 issuer_key=ca.key issuer_name=CN=fb_steigtum_ca,O=tubaf,C=de is_ca=1 max_pathlen=0 output_file=ca.crt
		# 2. Backend-Server:
		mbedtls_gen_key type=rsa rsa_keysize=4096 filename=backend_srv.key format=pem
		mbedtls_cert_write issuer_crt=ca.crt subject_key=backend_srv.key subject_name=CN=fb_steigtum_backend_srv,O=tubaf,C=de output_file=backend_srv.crt
		# 3. Backend-Subscription:
		mbedtls_gen_key type=rsa rsa_keysize=4096 filename=backend_subscript.key format=pem
		mbedtls_cert_write issuer_crt=ca.crt subject_key=backend_subscript.key subject_name=CN=fb_steigtum_backend_subscript,O=tubaf,C=de output_file=backend_subscript.crt
		# 4. App-Client:
		mbedtls_gen_key type=rsa rsa_keysize=4096 filename=app_clt.key format=pem
		mbedtls_cert_write issuer_crt=ca.crt subject_key=app_clt.key subject_name=CN=fb_steigtum_app_clt,O=tubaf,C=de output_file=app_clt.crt
		# 5. Fahrrad-µController-Server (optional ein eigenes Zertifikat *pro Fahrrad*):
		mbedtls_gen_key type=rsa rsa_keysize=4096 filename=bike_srv.key format=pem
		mbedtls_cert_write issuer_crt=ca.crt subject_key=bike_srv.key subject_name=CN=fb_steigtum_bike_srv,O=tubaf,C=de output_file=bike_srv.crt
		```
	- in `l2cap_server/` make the dir `spiffs_image/crypto/`
	- copy following files from `certs/` into into the dir <!-- TODO update dir--> `l2cap_server/spiffs_image/crypto/`:
		- `bike_srv.key`
		- `bike_srv.crt`
		- `ca.crt`
	- in `l2cap_client/` make the dir <!-- TODO update dir-->`spiffs_image/crypto/`
	- copy following files from `certs/` into into the dir <!-- TODO update dir--> `l2cap_client/spiffs_image/crypto/`:
		- `app_clt.crt`
		- `app_clt.key`
		- `backend_subscript.crt`
		- `backend_subscript.key`
		- `ca.crt`
	</p>
	</details>

	<!-- TODO: add debug stuff maybe -->



## 3. Build

### ESP32 App:
- depends on how you made your choice in the [Get-Started-Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
- Hint: if esp-idf was installed manually, in <!-- TODO update dir--> `l2cap_server/` run
	```
	$ idf.py -p PORT size flash monitor
	```

### Android App:
- TODO



## 4. Application Details

<!-- TODO: General details like throughput -->

### Connection Establishment
| Server | Client |
| --- | --- |
| Start advertising (GAP) | Start discovering (GAP) |
| | --> Discovered server |
| | <-- Connecting (GAP) to server |
| Connected to client (GAP) | Connected to server (GAP) |
| | |
| | <-- Connect to server (L2CAP) |
| Accepting connection (L2CAP) <-- | |
| Connected to client (L2CAP) | Connected to server (L2CAP) |
| | |
| TLS-Handshake | TLS-Handshake |
| Secure communication | Secure communication |
| | |
| | <-- Send subscription |
| Receive and verify subscription <-- | |

### Subscription
Concerning the project [SteigtUM](https://www.interaktive-technologien.de/projekte/steigtum) (a bike sharing service; user is client, bike is server) the subscription is used to make sure that the user is authorized to rent the bike.

<details><summary> Details </summary>
<p>
Subscriptions are used to verify as a server (bike) if a client is authorized to rent this bike. 
Because this is just a prototype, the subscription payload is flashed to the client application but in a real application the client must request and receive a subscription from the back end server as you can see in the following graphic:

<img src="./doc/graphics/subscription.svg">

<!-- TODO ist Backend nun intermediate CA und erstellt sub cert und sub key selbst? Wie soll sonst das sub cert von der Root CA erstellt werden ohn e den sub key zu übertragen? -->

The subscription certificate must be previously issued by a CA. The subscription certificate and key should be used for all subscriptions in a longer period, so you don't have to create a subscription for each renting.

When the server (bike) verifies the subscription, it checks the common name of the subscription certificate.
That means you should verify for the same common name you defined in the subscription certificate.
At the moment the server checks for the common name `fb_steigtum_backend_subscript`.

**Structure of the Subscription:**

```
- length of payload (2 bytes)
- payload
- length of payload signature (2 bytes)
- payload signature
- length of signer certificate (2 bytes)
- signer certificate
```

To adjust the content of the payload edit `l2cap_client/spiffs/crypto/` <!-- TODO or `the android app project` --> . Then rebuild the application.
</p>
</details>

### ESP
#### Tasks / Threading
Because this ESP32 contains a dual core processor FreeRTOS-Tasks are either pinned to PRO_CPU (ID = 0, Protocol CPU) or APP_CPU (ID = 1, Application CPU).
- PRO_CPU (0) Tasks:
	- NimBLE Host
	- the app itself
- APP_CPU (1) Tasks:

#### Configuration
In `l2cap_server/` and `l2cap_client/` the following configurations are done already.
- **required for mbedtls debugging**
	- in `esp_apis/ssl_ctx.h` set line 5 to `#define SSL_CTX_DEBUG` <!-- TODO Maybe adjust location and line -->
	- in a ESP-IDF-Project like `l2cap_server/` or `l2cap_client/` run `idf.py menuconfig` and adjust the following values:
		- _Component config_ ->
			- _mbedTLS_ -> _Enable mbedTLS debugging_ -> set true = (*)
			- _ESP System Settings_ -> _Main task stack size_ -> 6000 works definitely, standard value was 3584 (increase if running into a stack overflow in task main)
			- _ESP System Settings_ -> _Channel for console output_ -> _Custom UART_
			- _ESP System Settings_ -> _UART console baud rate_ -> 230400
		- _Serial flasher config_ -> _`idf.py monitor` baud rate_ -> 230400



## 5. Links and Examples to Get Started
### ESP-IDF
- [build system](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html)
- [partition table](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/partition-tables.html)
	- [custom tables](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/partition-tables.html#creating-custom-tables)
- [SPIFFS Filesystem](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/spiffs.html)
- SPIFFS example: in your esp directory, `path/to/.../esp/esp-idf/examples/storage/spiffsgen`
- <!-- TODO Maybe remove -->GATT server example: in your esp directory, `path/to/.../esp/esp-idf/examples/bluetooth/bluedroid/ble/gatt_server`
- NimBLE btshell example (includes GAP, L2CAP, GATT, but adjustments for esp32 necessary): in your esp dir, `path/to/.../esp/esp-idf/components/bt/host/nimble/nimble/apps/btshell`
### mbedtls:
- [knowledge base / how to](https://tls.mbed.org/kb/how-to) or [knowledge base](https://tls.mbed.org/kb) in general
	- [mbedtls tutorial](https://tls.mbed.org/kb/how-to/mbedtls-tutorial)



## 6. Continuation


---

<!--
## Developing ESP32
- install the [Arduino IDE](https://www.arduino.cc/en/software)
	- follow this [ESP32 Manual](https://joy-it.net/files/files/Produkte/SBC-NodeMCU-ESP32/SBC-NodeMCU-ESP32-Manual-20200320.pdf)
	- install the "ESP32 BLE Arduino" library ([further information](https://www.arduino.cc/reference/en/libraries/esp32-ble-arduino/))
		- open the Arduino IDE -> Tools -> Manage Libraries -> Search "ESP32 BLE Arduino" -> install
-->