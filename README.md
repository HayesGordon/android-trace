# android-trace
[Frida-node](https://github.com/frida/frida-node) cli tool for automating Android class and method tracing.
### Installation
android-trace requires the following:
* [Node.js](https://nodejs.org/) v4+ to run, including Node package manager NPM.
* [Android Platform Tools](https://developer.android.com/studio/releases/platform-tools.html), specifically ADB (Android Debug Bridge). ADB must be added to the PATH environment.

Installing Node for Debian and Ubuntu based Linux distributions:
```sh
$ curl -sL https://deb.nodesource.com/setup_6.x | sudo -E bash -
$ sudo apt-get install -y nodejs
```
Installing android-trace:
```sh
$ git clone https://github.com/postgor/android-trace
$ cd android-trace
$ npm install
```

### Usage
Currently android-trace only supports [Frida](https://www.frida.re/) over USB; make sure the device or emulator is visible over ADB. To connect to an Android emulator:
```sh
$ adb connect {emulator IP addres}
```
Make sure only one device is visible over ADB.
Frida has issues hooking certain methods and classes; on fail, exclude the classes and methods that caused the error condition.

### Example
Hook all loaded classes and methods. Proceed with caution.
```sh
$ node index.js -n {package name}
```
Specify -f to only include classes/methods that match a given filter. A good idea would be to filter by package name or a name unique to the application's naming convention.
```sh
$ node index.js -n {package name} -f {filter}
```
Specify -E along with a comma separated list of classes to exclude (no spaces). Provide the full package and class path to ensure only the specified classes get excluded.
```sh
$ node index.js -n {package name} -E com.androidtrace.testapp.MyClass,ClassesContaingString
```
Specify -e along with a comma separated list of methods to exclude. Note that the script will exclude all methods matching the provided string.
```sh
$ node index.js -n {package name} -E Method1,MethodContaingString
```
