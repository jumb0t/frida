// frida_enhanced_hook.js

function sendMessage(type, data) {
    var message = {
        'type': type,
        'data': data,
        'timestamp': new Date().toISOString()
    };
    send(message);
}

function decodeString(encodedStr) {
    try {
        // Попытка декодировать Base64
        var decodedBase64 = atob(encodedStr);
        return decodedBase64;
    } catch (e) {
        // Если не Base64, возвращаем оригинальную строку
        return encodedStr;
    }
}

Java.perform(function () {
    // Улучшенное логирование
    function log(message) {
        console.log(`[${new Date().toISOString()}] ${message}`);
    }

    // Hooking android.os.Build properties
    try {
        var Build = Java.use('android.os.Build');
        var buildFields = [
            'MODEL', 'MANUFACTURER', 'BRAND', 'DEVICE', 'PRODUCT', 'HARDWARE', 'FINGERPRINT',
            'SERIAL', 'ID', 'TAGS', 'TYPE', 'USER', 'DISPLAY', 'HOST'
        ];

        buildFields.forEach(function (field) {
            var originalValue = Build[field].value;
            Object.defineProperty(Build, field, {
                get: function () {
                    var value = decodeString(originalValue);
                    log(`[+] Hooked android.os.Build.${field}: ${value}`);
                    sendMessage('hook', {
                        'hooked_method': 'android.os.Build.' + field,
                        'value': value
                    });
                    return originalValue;
                },
                set: function (newValue) {
                    originalValue = newValue;
                }
            });
        });

        var VERSION = Java.use('android.os.Build$VERSION');
        var versionFields = ['SDK_INT', 'RELEASE', 'INCREMENTAL', 'CODENAME', 'BASE_OS', 'SECURITY_PATCH'];

        versionFields.forEach(function (field) {
            var originalValue = VERSION[field].value;
            Object.defineProperty(VERSION, field, {
                get: function () {
                    var value = decodeString(originalValue);
                    log(`[+] Hooked android.os.Build.VERSION.${field}: ${value}`);
                    sendMessage('hook', {
                        'hooked_method': 'android.os.Build.VERSION.' + field,
                        'value': value
                    });
                    return originalValue;
                },
                set: function (newValue) {
                    originalValue = newValue;
                }
            });
        });

        Build.getSerial.overload().implementation = function () {
            var ret = this.getSerial();
            var value = decodeString(ret);
            log(`[+] Hooked android.os.Build.getSerial(): ${value}`);
            sendMessage('hook', {
                'hooked_method': 'android.os.Build.getSerial()',
                'return_value': value
            });
            return ret;
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking android.os.Build: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.os.SystemProperties methods
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');

        SystemProperties.get.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = arguments;
                var ret = overload.apply(this, args);
                var value = decodeString(ret);
                log(`[+] Hooked android.os.SystemProperties.get(${Array.prototype.join.call(args, ', ')}): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'android.os.SystemProperties.get',
                    'args': args,
                    'return_value': value
                });
                return ret;
            };
        });

        SystemProperties.getInt.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = arguments;
                var ret = overload.apply(this, args);
                log(`[+] Hooked android.os.SystemProperties.getInt(${Array.prototype.join.call(args, ', ')}): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'android.os.SystemProperties.getInt',
                    'args': args,
                    'return_value': ret
                });
                return ret;
            };
        });

        SystemProperties.getLong.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = arguments;
                var ret = overload.apply(this, args);
                log(`[+] Hooked android.os.SystemProperties.getLong(${Array.prototype.join.call(args, ', ')}): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'android.os.SystemProperties.getLong',
                    'args': args,
                    'return_value': ret
                });
                return ret;
            };
        });

        SystemProperties.getBoolean.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = arguments;
                var ret = overload.apply(this, args);
                log(`[+] Hooked android.os.SystemProperties.getBoolean(${Array.prototype.join.call(args, ', ')}): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'android.os.SystemProperties.getBoolean',
                    'args': args,
                    'return_value': ret
                });
                return ret;
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking android.os.SystemProperties: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking java.lang.Runtime.exec
    try {
        var Runtime = Java.use('java.lang.Runtime');

        Runtime.exec.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = arguments;
                log(`[+] Hooked java.lang.Runtime.exec(${Array.prototype.join.call(args, ', ')})`);
                sendMessage('hook', {
                    'hooked_method': 'java.lang.Runtime.exec',
                    'args': args
                });
                return overload.apply(this, args);
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking java.lang.Runtime: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking java.lang.System.getProperty
    try {
        var SystemClass = Java.use('java.lang.System');

        SystemClass.getProperty.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = arguments;
                var ret = overload.apply(this, args);
                var value = decodeString(ret);
                log(`[+] Hooked java.lang.System.getProperty(${Array.prototype.join.call(args, ', ')}): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'java.lang.System.getProperty',
                    'args': args,
                    'return_value': value
                });
                return ret;
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking java.lang.System: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.provider.Settings.Secure.getString
    try {
        var SettingsSecure = Java.use('android.provider.Settings$Secure');

        SettingsSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (resolver, name) {
            var ret = this.getString(resolver, name);
            var value = decodeString(ret);
            log(`[+] Hooked android.provider.Settings.Secure.getString("${name}"): ${value}`);
            sendMessage('hook', {
                'hooked_method': 'android.provider.Settings.Secure.getString',
                'args': { 'name': name },
                'return_value': value
            });
            return ret;
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking android.provider.Settings.Secure: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.telephony.TelephonyManager methods
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');

        TelephonyManager.getDeviceId.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var ret = overload.apply(this, arguments);
                var value = decodeString(ret);
                log(`[+] Hooked TelephonyManager.getDeviceId(): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'TelephonyManager.getDeviceId',
                    'return_value': value
                });
                return ret;
            };
        });

        TelephonyManager.getImei.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var ret = overload.apply(this, arguments);
                var value = decodeString(ret);
                log(`[+] Hooked TelephonyManager.getImei(): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'TelephonyManager.getImei',
                    'return_value': value
                });
                return ret;
            };
        });

        TelephonyManager.getSubscriberId.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var ret = overload.apply(this, arguments);
                var value = decodeString(ret);
                log(`[+] Hooked TelephonyManager.getSubscriberId(): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'TelephonyManager.getSubscriberId',
                    'return_value': value
                });
                return ret;
            };
        });

        TelephonyManager.getSimSerialNumber.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var ret = overload.apply(this, arguments);
                var value = decodeString(ret);
                log(`[+] Hooked TelephonyManager.getSimSerialNumber(): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'TelephonyManager.getSimSerialNumber',
                    'return_value': value
                });
                return ret;
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking TelephonyManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.net.wifi.WifiInfo.getMacAddress
    try {
        var WifiInfo = Java.use('android.net.wifi.WifiInfo');

        WifiInfo.getMacAddress.implementation = function () {
            var ret = this.getMacAddress();
            var value = decodeString(ret);
            log(`[+] Hooked WifiInfo.getMacAddress(): ${value}`);
            sendMessage('hook', {
                'hooked_method': 'WifiInfo.getMacAddress',
                'return_value': value
            });
            return ret;
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking WifiInfo: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.os.Environment methods
    try {
        var Environment = Java.use('android.os.Environment');

        Environment.getExternalStorageDirectory.implementation = function () {
            var ret = this.getExternalStorageDirectory();
            log(`[+] Hooked Environment.getExternalStorageDirectory(): ${ret}`);
            sendMessage('hook', {
                'hooked_method': 'Environment.getExternalStorageDirectory',
                'return_value': ret
            });
            return ret;
        };

        Environment.getExternalStorageState.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var ret = overload.apply(this, arguments);
                log(`[+] Hooked Environment.getExternalStorageState(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'Environment.getExternalStorageState',
                    'return_value': ret
                });
                return ret;
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking Environment: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.content.pm.PackageManager.getInstalledPackages
    try {
        var PackageManager = Java.use('android.content.pm.PackageManager');

        PackageManager.getInstalledPackages.overloads.forEach(function (overload) {
            overload.implementation = function (flags) {
                var ret = overload.apply(this, arguments);
                log(`[+] Hooked PackageManager.getInstalledPackages(${flags})`);
                sendMessage('hook', {
                    'hooked_method': 'PackageManager.getInstalledPackages',
                    'args': { 'flags': flags },
                    'return_value': ret
                });
                return ret;
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking PackageManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.bluetooth.BluetoothAdapter.getAddress
    try {
        var BluetoothAdapter = Java.use('android.bluetooth.BluetoothAdapter');

        BluetoothAdapter.getAddress.implementation = function () {
            var ret = this.getAddress();
            var value = decodeString(ret);
            log(`[+] Hooked BluetoothAdapter.getAddress(): ${value}`);
            sendMessage('hook', {
                'hooked_method': 'BluetoothAdapter.getAddress',
                'return_value': value
            });
            return ret;
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking BluetoothAdapter: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.app.ActivityManager.getRunningAppProcesses
    try {
        var ActivityManager = Java.use('android.app.ActivityManager');

        ActivityManager.getRunningAppProcesses.implementation = function () {
            var ret = this.getRunningAppProcesses();
            log(`[+] Hooked ActivityManager.getRunningAppProcesses()`);
            sendMessage('hook', {
                'hooked_method': 'ActivityManager.getRunningAppProcesses',
                'return_value': ret
            });
            return ret;
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking ActivityManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Native hook for __system_property_get
    try {
        var libName = "libc.so";
        var funcName = "__system_property_get";
        var system_property_get = null;

        Process.enumerateModules().forEach(function (module) {
            if (module.name.indexOf("libc") >= 0) {
                system_property_get = Module.findExportByName(module.name, funcName);
                if (system_property_get) {
                    libName = module.name;
                    return false;
                }
            }
        });

        if (system_property_get) {
            Interceptor.attach(system_property_get, {
                onEnter: function (args) {
                    this.key = args[0].readUtf8String();
                    this.value_ptr = args[1];
                    log(`[+] Hooked __system_property_get("${this.key}")`);
                    sendMessage('native_hook', {
                        'hooked_function': '__system_property_get',
                        'args': { 'key': this.key }
                    });
                },
                onLeave: function (retval) {
                    var value = decodeString(this.value_ptr.readUtf8String());
                    log(`[+] __system_property_get result for "${this.key}": ${value}`);
                    sendMessage('native_hook', {
                        'hooked_function': '__system_property_get',
                        'return_value': value,
                        'args': { 'key': this.key }
                    });
                }
            });
        } else {
            var errorMsg = `[-] ${funcName} not found in any libc module`;
            console.error(errorMsg);
            sendMessage('error', { 'message': errorMsg });
        }
    } catch (e) {
        var errorMsg = `[-] Error hooking __system_property_get: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking JNI method System.getProperty
    try {
        var system_getProperty = Module.findExportByName(null, 'Java_java_lang_System_getProperty');
        if (system_getProperty) {
            Interceptor.attach(system_getProperty, {
                onEnter: function (args) {
                    var env = args[0];
                    var javaString = args[1];
                    var jstring = Java.vm.getEnv().getStringUTFChars(javaString, null).readCString();
                    this.propertyName = jstring;
                    log(`[+] Hooked native System.getProperty("${this.propertyName}")`);
                    sendMessage('native_hook', {
                        'hooked_function': 'Java_java_lang_System_getProperty',
                        'args': { 'propertyName': this.propertyName }
                    });
                },
                onLeave: function (retval) {
                    // Обработка возвращаемого значения может быть сложной в JNI
                }
            });
        }
    } catch (e) {
        var errorMsg = `[-] Error hooking native System.getProperty: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }
});
