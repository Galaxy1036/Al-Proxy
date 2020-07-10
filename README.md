# Al-Proxy
 An MITM proxy for Arcane Legends Mobile & Browser MMORPG game 

## Information

Arcane Legends is a Mobile & Browser MMORPG game, the game actually use a custom network protocol & packets format.
The goal of this repository is to capture all the game packets and decrypt encrypted one.

## How to use it
First of all you will need to build a modded apk with a custom certificate in it in order to allow the proxy to decrypt your game packets.

### Creating certificate & private key
Make sure you have **openssl** installed before running the following commands.

To build the certificate & private key use the following command:
> openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout private_key.pem -out cert.pem

Then convert the certificate to DER format using the following command:
> openssl x509 -outform der -in cert.pem -out cert.der

### Building a modded apk
Steps:

1. Download the original Arcane Legends APK
2. Extract files from it with [apktool](https://ibotpeaches.github.io/Apktool/)
3. Grab out `android000.png` from the `assets` folder and extract files from it using [my extractor](https://github.com/Galaxy1036/AL-Assets-RE/blob/master/al_pak_extractor.py)
4. Replace the extracted `public_key/92700.der` file with your own `cert.der` **Make sure to rename it to 92700.der !**
5. Build your new modded `android000.png` using [my packer](https://github.com/Galaxy1036/AL-Assets-RE/blob/master/al_pak_packer.py)
6. Replace the original `android000.png` in the extracted apk files with the one you created
7. Build the modified apk with apktool
8. Sign the modified apk, [apksigner](https://developer.android.com/studio/command-line/apksigner) can be used to do it
9. Install your modified apk :)

### Forwarding your game traffic to the proxy
You got two options to do that:

- Edit your `/etc/hosts` file if your device is rooted and redirect `account.spacetimestudios.com` to the ip the proxy is running on
- Manually edit `authServerAddress` variable in the apk file `assets/Client.cfg`. **Note**: this will require you to rebuild the apk and sign it

To make the proxy correctly redirect all your game traffic to it you need to set **TCPHost** key in **config.json** to the ip the proxy is running on (most likely you computer local ip)
### Options
**Al-Proxy** also take a few optionals arguments that are:

* `-v`, `--verbose`: if specified packet hexdump will be displayed in the console, can be useful to look at packet content in real-time
* `-r`, `--replay`: if specified packet data will be saved in the directory specified in **config.json** 
* `-f`, `--frida`: if specified, the game will be automatically launched on your device and the frida script will be injected at proxy runtime to dump packet names from your device memory. **Note**: This might slow down your game

## Dependencies
The proxy need some external dependencies to run:

**If you want the frida script to be injected at proxy runtime:**

- Setup **frida-server** on your device, here is a guide: [https://www.frida.re/docs/android/](https://www.frida.re/docs/android/)

To install others needed dependencies run the following command:
> python -m pip install -r requirements.txt

## TODO List
- Implement server side crypto, couldn't find any encrypted server packet so i didn't implemented it, if you find any make sure to create an issue

## Contact me
Do you have any questions or bugs to report? Feel free to contact me at @GaLaXy1036#1601 on Discord!

