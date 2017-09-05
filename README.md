# android-trace
[Frida-node](https://github.com/frida/frida-node) CLI tool for automating Android class and method tracing.
### Installation
android-trace requires the following:
* [Node.js](https://nodejs.org/) v4+ to run, including node package manager NPM.
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

### Setup
##### Frida-Server
See [frida android](https://www.frida.re/docs/android/) for the full documentation on how to get Frida up and running for Android.

Download the latest frida-server from [frida-releases](https://github.com/frida/frida/releases) for your Android platfrom architecture.

Extract xz archive
```sh
$ xz -d frida-server-{version}-android-{architecture}.xz {emulator IP addres}
```

Get frida-server running on your android device/emulator
```sh
$ adb root # might be required
$ adb push frida-server /data/local/tmp/
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "/data/local/tmp/frida-server &"
```

If you prefer to connect to the frida-server over a network instead of USB, substititute:
```sh
$ adb shell "/data/local/tmp/frida-server &"
```
for:
```sh
$ adb shell "/data/local/tmp/frida-server -l {device-ip:listening-port}"
```

Finally, make sure android-trace is working. As a test, see if you can list the device's running processes.
Over USB:
```sh
$ node index.js -U -r}
```
Over HOST:
```sh
$ node index.js -H {device-ip:listening-port} -r
```

### Ussage

##### Hook all the things
Proceed with caution - generally it is not a good idea to hook every single class/method. Provide the application's package name:
```sh
$ node index.js -U -n {package name}
```
or substitute package name for process id:
```sh
$ node index.js -U -p {pid}
```
##### Filtering by class
The package com.androidtrace.test will be used as an example. Pretend this package has the following classes and methods:
- myClass1 [myMethod1, myMethod2, myMethod3]
- myClass2 [myMethod1, myMethod2, myMethod3]
- myClass3 [myMethod1, myMethod2, myMethod3]

Specify -F to only include classes that match a provided regex. A good idea would be to filter by package name or a name unique to the application's naming convention. For example, the below will hook all the classes that have the class-path "com.androidtrace.test".

```sh
$ node index.js -U -n {package name} -F "com.androidtrace.test"
```

If you only want to hook "myClass1", you can apply one of the following filters:
- "com.androidtrace.test.myClass1"
- "androidtrace.*myClass1"
- "myClass1"

Note that a filter such as "myClass1" will hook other class-paths containing a match for "myClass1". For example, "com.android.myClass1SomethingElse".

To include multiple filters, you can apply normal regex rules, for example:
```sh
$ node index.js -U -n {package name} -F "myClass1|myClass2"
```
This will find matches for both "myClass1" and "myClass2".

##### Filtering by function

The same rules for filtering by class name apply to filtering by method. Specify "-f" to filter by method name. For example to only hook the "myMethod2" function of the "myClass3" class, the following filter can be applied:
```sh
$ node index.js -U -n {package name} -F "androidtrace.*myClass3" -f "myMethod2"
```

Note that you can also exclude the class filter (-F), however this will result in the script calling "Frida.use" on every enumerated class in order to discover the available methods. This could result in performance issues, and errors. It is best practice to always supply a class filter.

##### Excluding classes and methods

Same rules as above, only inverse. For example, hook all the classes with a certain class-path, except myClass2:
```sh
$ node index.js -U -n {package name} -F "com.androidtrace.test" -E "myClass2"
```

Hook all the methods in a certain class except "myMethod1" and "myMethod2":
```sh
$ node index.js -U -n {package name} -F "com.androidtrace.test" -e "myMethod1|myMethod2"
```

##### Trace classes from provided file
android-trace allows you to provide a "json" file containing a list of classes that you want to trace. For example:

```sh
$ node index.js -U -n {package name} -l classes.json
```

["com.androidtrace.test.MyClass1","com.androidtrace.test.MyClass2"]
