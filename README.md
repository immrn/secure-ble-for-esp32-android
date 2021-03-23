# secure-ble-for-esp32-android
1. [Prerequisites](#1.-Prerequisites)
2. [Before Building](#2.-Before-Building)
3. [Build](#3.-Build)
4. [How It Works](#4.-How-It-Works)
5. [Links and Examples to Get Started](#5.-Links-and-Examples-to-Get-Started)
6. [Continuation](#6.-Continuation)

## 1. Prerequisites

### Hardware:
- Microcontroller: [SBC-NodeMCU ESP32](https://joy-it.net/en/products/SBC-NodeMCU-ESP32)
- Android device: Android 6.0 or higher

### Software:
- ESP-IDF: follow the [Get-Started-Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
	- to follow this README it's recommended to [install the software manually](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
	- after installing you should [build mbedtls](https://tls.mbed.org/kb/compiling-and-building/how-do-i-build-compile-mbedtls) in `esp/esp-idf/components/mbedtls/mbedtls/`, this is necessary to run certificate and key generation later
	<!--	- mbedtls: download [here](https://tls.mbed.org/download) or install via a package manager (Ubuntu: `$ sudo apt install libmbedtls-dev`) -->
- [Android Studio](https://developer.android.com/studio)

## 2. Before Building

### Generate the Certificate Chain:
- **if using Linux/MacOS**:
	- in `secure-ble-for-esp32-android` run the following (for more information look into `gen_cert_chain.sh`)
		```
		$ chmod +x ./gen_cert_chain.sh
		$ ./gen_cert_chain.sh PATH/TO/ESP/DIRECTORY
		```
- **else**:
	<details><summary>Click here</summary>
	<p>

	- make a dir `certs`, go into `certs`
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
	- in dir `gatt_server` make the dir `spiffs_image/crypto`
	- copy `bike_srv.key`, `bike_srv.crt` and `ca.crt` from dir `certs` into the dir <!-- TODO --> `gatt_server/spiffs_image/crypto`
	</p>
	</details>

	<!-- TODO: add debug stuff maybe -->

## 3. Build

### ESP32 App:
- depends on how you made your choice in the [Get-Started-Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
- Hint: if esp-idf was installed manually, in <!-- TODO --> `gatt_server` run
	```
	$ idf.py -p PORT size flash monitor
	```

### Android App:

## 4. How It Works
<!-- Explain TLS over BLE ... -->

## 5. Links and Examples to Get Started
### ESP-IDF
- [build system](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html)
- [partition table](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/partition-tables.html)
	- [custom tables](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/partition-tables.html#creating-custom-tables)
- [SPIFFS Filesystem](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/storage/spiffs.html)
- SPIFFS example: in your esp directory, path/to/.../esp/esp-idf/examples/storage/spiffsgen
- GATT server example: in your esp directory, path/to/.../esp/esp-idf/examples/bluetooth/bluedroid/ble/gatt_server
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