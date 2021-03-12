# secure-ble-for-esp32-android
<!-- use ToC -->
## Prerequisites
- Hardware:
	- Microcontroller: [SBC-NodeMCU ESP32](https://joy-it.net/en/products/SBC-NodeMCU-ESP32)
	- Android device: Android 6.0 or higher (or use the Android Studio emulator)
- Software:
	- ESP-IDF: follow the [Get-Started-Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
		- to follow this README it's recommended to [install the software manually](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
	- mbedtls: download [here](https://tls.mbed.org/download) or install via a package manager (Ubuntu: `$ sudo apt install libmbedtls-dev`)
	- [Android Studio](https://developer.android.com/studio)

## Build
- ESP32 App: depends on how you made your choice in the [Get-Started-Guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html)
	- Hint: call `$ idf.py -p /dev/ttyUSB0 size flash monitor` in the directory of your esp-app
- Android App:
## Structure
<!-- TLS over BLE ... -->

## Links and Examples to get started
- esp-idf:
	- GATT server example: probably in your HOME directory at /esp/esp-idf/examples/bluetooth/bluedroid/ble/gatt_server
- mbedtls:
	- [knowledge base / how to](https://tls.mbed.org/kb/how-to) or [knowledge base](https://tls.mbed.org/kb) in general
		- [mbedtls tutorial](https://tls.mbed.org/kb/how-to/mbedtls-tutorial)

## Continuation


---

<!--
## Developing ESP32
- install the [Arduino IDE](https://www.arduino.cc/en/software)
	- follow this [ESP32 Manual](https://joy-it.net/files/files/Produkte/SBC-NodeMCU-ESP32/SBC-NodeMCU-ESP32-Manual-20200320.pdf)
	- install the "ESP32 BLE Arduino" library ([further information](https://www.arduino.cc/reference/en/libraries/esp32-ble-arduino/))
		- open the Arduino IDE -> Tools -> Manage Libraries -> Search "ESP32 BLE Arduino" -> install
-->