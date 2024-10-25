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
    }

    try {
        // Попытка декодировать URI компонент
        return decodeURIComponent(encodedStr);
    } catch (e) {
        // Если не удалось декодировать, возвращаем оригинальную строку
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
            'SERIAL', 'ID', 'TAGS', 'TYPE', 'USER', 'DISPLAY', 'HOST',
            // Дополнительные поля
            'SUPPORTED_ABIS', 'SUPPORTED_32_BIT_ABIS', 'SUPPORTED_64_BIT_ABIS', 'CPU_ABI', 'CPU_ABI2'
        ];

        buildFields.forEach(function (field) {
            try {
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
            } catch (e) {
                log(`[-] Could not hook android.os.Build.${field}: ${e.message}`);
            }
        });

        var VERSION = Java.use('android.os.Build$VERSION');
        var versionFields = ['SDK_INT', 'RELEASE', 'INCREMENTAL', 'CODENAME', 'BASE_OS', 'SECURITY_PATCH', 'PREVIEW_SDK_INT'];

        versionFields.forEach(function (field) {
            try {
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
            } catch (e) {
                log(`[-] Could not hook android.os.Build.VERSION.${field}: ${e.message}`);
            }
        });

        Build.getSerial.overload().implementation = function () {
            try {
                var ret = this.getSerial();
                var value = decodeString(ret);
                log(`[+] Hooked android.os.Build.getSerial(): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'android.os.Build.getSerial()',
                    'return_value': value
                });
                return ret;
            } catch (e) {
                log(`[-] Error in Build.getSerial(): ${e.message}`);
                return this.getSerial();
            }
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
                try {
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
                } catch (e) {
                    log(`[-] Error in SystemProperties.get(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
            };
        });

        SystemProperties.getInt.overloads.forEach(function (overload) {
            overload.implementation = function () {
                try {
                    var args = arguments;
                    var ret = overload.apply(this, args);
                    log(`[+] Hooked android.os.SystemProperties.getInt(${Array.prototype.join.call(args, ', ')}): ${ret}`);
                    sendMessage('hook', {
                        'hooked_method': 'android.os.SystemProperties.getInt',
                        'args': args,
                        'return_value': ret
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in SystemProperties.getInt(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
            };
        });

        SystemProperties.getLong.overloads.forEach(function (overload) {
            overload.implementation = function () {
                try {
                    var args = arguments;
                    var ret = overload.apply(this, args);
                    log(`[+] Hooked android.os.SystemProperties.getLong(${Array.prototype.join.call(args, ', ')}): ${ret}`);
                    sendMessage('hook', {
                        'hooked_method': 'android.os.SystemProperties.getLong',
                        'args': args,
                        'return_value': ret
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in SystemProperties.getLong(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
            };
        });

        SystemProperties.getBoolean.overloads.forEach(function (overload) {
            overload.implementation = function () {
                try {
                    var args = arguments;
                    var ret = overload.apply(this, args);
                    log(`[+] Hooked android.os.SystemProperties.getBoolean(${Array.prototype.join.call(args, ', ')}): ${ret}`);
                    sendMessage('hook', {
                        'hooked_method': 'android.os.SystemProperties.getBoolean',
                        'args': args,
                        'return_value': ret
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in SystemProperties.getBoolean(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
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
                try {
                    var args = arguments;
                    log(`[+] Hooked java.lang.Runtime.exec(${Array.prototype.join.call(args, ', ')})`);
                    sendMessage('hook', {
                        'hooked_method': 'java.lang.Runtime.exec',
                        'args': args
                    });
                    return overload.apply(this, args);
                } catch (e) {
                    log(`[-] Error in Runtime.exec(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
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
                try {
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
                } catch (e) {
                    log(`[-] Error in System.getProperty(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
            };
        });

        // Перехват java.lang.System.getenv()
        SystemClass.getenv.overloads.forEach(function (overload) {
            overload.implementation = function () {
                try {
                    var args = arguments;
                    var ret = overload.apply(this, args);
                    log(`[+] Hooked java.lang.System.getenv(): ${ret}`);
                    sendMessage('hook', {
                        'hooked_method': 'java.lang.System.getenv',
                        'args': args,
                        'return_value': ret
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in System.getenv(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
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
            try {
                var ret = this.getString(resolver, name);
                var value = decodeString(ret);
                log(`[+] Hooked android.provider.Settings.Secure.getString("${name}"): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'android.provider.Settings.Secure.getString',
                    'args': { 'name': name },
                    'return_value': value
                });
                return ret;
            } catch (e) {
                log(`[-] Error in Settings.Secure.getString(): ${e.message}`);
                return this.getString(resolver, name);
            }
        };

        // Hooking android.provider.Settings.Secure.ANDROID_ID
        Object.defineProperty(SettingsSecure, 'ANDROID_ID', {
            get: function () {
                try {
                    var value = decodeString(SettingsSecure.ANDROID_ID.value);
                    log(`[+] Hooked android.provider.Settings.Secure.ANDROID_ID: ${value}`);
                    sendMessage('hook', {
                        'hooked_method': 'android.provider.Settings.Secure.ANDROID_ID',
                        'value': value
                    });
                    return SettingsSecure.ANDROID_ID.value;
                } catch (e) {
                    log(`[-] Error in accessing Settings.Secure.ANDROID_ID: ${e.message}`);
                    return SettingsSecure.ANDROID_ID.value;
                }
            },
            set: function (newValue) {
                SettingsSecure.ANDROID_ID.value = newValue;
            }
        });

        // Hook ALLOWED_GEOLOCATION_ORIGINS and DEFAULT_INPUT_METHOD
        ['ALLOWED_GEOLOCATION_ORIGINS', 'DEFAULT_INPUT_METHOD'].forEach(function (field) {
            Object.defineProperty(SettingsSecure, field, {
                get: function () {
                    try {
                        var value = decodeString(SettingsSecure[field].value);
                        log(`[+] Hooked Settings.Secure.${field}: ${value}`);
                        sendMessage('hook', {
                            'hooked_method': `Settings.Secure.${field}`,
                            'value': value
                        });
                        return SettingsSecure[field].value;
                    } catch (e) {
                        log(`[-] Error in accessing Settings.Secure.${field}: ${e.message}`);
                        return SettingsSecure[field].value;
                    }
                },
                set: function (newValue) {
                    SettingsSecure[field].value = newValue;
                }
            });
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking android.provider.Settings.Secure: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.telephony.TelephonyManager methods
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');

        ['getDeviceId', 'getImei', 'getSubscriberId', 'getSimSerialNumber', 'getNetworkOperatorName', 'getPhoneType', 'getCellLocation'].forEach(function (methodName) {
            TelephonyManager[methodName].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    try {
                        var ret = overload.apply(this, arguments);
                        var value = decodeString(ret);
                        log(`[+] Hooked TelephonyManager.${methodName}(): ${value}`);
                        sendMessage('hook', {
                            'hooked_method': `TelephonyManager.${methodName}`,
                            'return_value': value
                        });
                        return ret;
                    } catch (e) {
                        log(`[-] Error in TelephonyManager.${methodName}(): ${e.message}`);
                        return overload.apply(this, arguments);
                    }
                };
            });
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
            try {
                var ret = this.getMacAddress();
                var value = decodeString(ret);
                log(`[+] Hooked WifiInfo.getMacAddress(): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'WifiInfo.getMacAddress',
                    'return_value': value
                });
                return ret;
            } catch (e) {
                log(`[-] Error in WifiInfo.getMacAddress(): ${e.message}`);
                return this.getMacAddress();
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking WifiInfo: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.app.ActivityManager methods
    try {
        var ActivityManager = Java.use('android.app.ActivityManager');

        ActivityManager.getRunningAppProcesses.implementation = function () {
            try {
                var ret = this.getRunningAppProcesses();
                log(`[+] Hooked ActivityManager.getRunningAppProcesses()`);
                sendMessage('hook', {
                    'hooked_method': 'ActivityManager.getRunningAppProcesses',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in ActivityManager.getRunningAppProcesses(): ${e.message}`);
                return this.getRunningAppProcesses();
            }
        };

        var MemoryInfo = Java.use('android.app.ActivityManager$MemoryInfo');

        ActivityManager.getMemoryInfo.overload('android.app.ActivityManager$MemoryInfo').implementation = function (outInfo) {
            try {
                this.getMemoryInfo(outInfo);
                log(`[+] Hooked ActivityManager.getMemoryInfo()`);
                sendMessage('hook', {
                    'hooked_method': 'ActivityManager.getMemoryInfo',
                    'return_value': outInfo
                });
            } catch (e) {
                log(`[-] Error in ActivityManager.getMemoryInfo(): ${e.message}`);
                this.getMemoryInfo(outInfo);
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking ActivityManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.location.LocationManager.getLastKnownLocation(String provider)
    try {
        var LocationManager = Java.use('android.location.LocationManager');

        LocationManager.getLastKnownLocation.overload('java.lang.String').implementation = function (provider) {
            try {
                var ret = this.getLastKnownLocation(provider);
                log(`[+] Hooked LocationManager.getLastKnownLocation("${provider}"): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'LocationManager.getLastKnownLocation',
                    'args': { 'provider': provider },
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in LocationManager.getLastKnownLocation(): ${e.message}`);
                return this.getLastKnownLocation(provider);
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking LocationManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.accounts.AccountManager.getAccounts()
    try {
        var AccountManager = Java.use('android.accounts.AccountManager');

        AccountManager.getAccounts.overload().implementation = function () {
            try {
                var ret = this.getAccounts();
                log(`[+] Hooked AccountManager.getAccounts(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'AccountManager.getAccounts',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in AccountManager.getAccounts(): ${e.message}`);
                return this.getAccounts();
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking AccountManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.net.ConnectivityManager methods
    try {
        var ConnectivityManager = Java.use('android.net.ConnectivityManager');

        ConnectivityManager.getActiveNetworkInfo.overload().implementation = function () {
            try {
                var ret = this.getActiveNetworkInfo();
                log(`[+] Hooked ConnectivityManager.getActiveNetworkInfo(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'ConnectivityManager.getActiveNetworkInfo',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in ConnectivityManager.getActiveNetworkInfo(): ${e.message}`);
                return this.getActiveNetworkInfo();
            }
        };

        // getAllNetworkInfo() устарел в API 23, проверяем его наличие
        if (ConnectivityManager.getAllNetworkInfo) {
            ConnectivityManager.getAllNetworkInfo.overload().implementation = function () {
                try {
                    var ret = this.getAllNetworkInfo();
                    log(`[+] Hooked ConnectivityManager.getAllNetworkInfo(): ${ret}`);
                    sendMessage('hook', {
                        'hooked_method': 'ConnectivityManager.getAllNetworkInfo',
                        'return_value': ret
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in ConnectivityManager.getAllNetworkInfo(): ${e.message}`);
                    return this.getAllNetworkInfo();
                }
            };
        }
    } catch (e) {
        var errorMsg = `[-] Error hooking ConnectivityManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.net.wifi.WifiManager methods
    try {
        var WifiManager = Java.use('android.net.wifi.WifiManager');

        WifiManager.getConnectionInfo.overload().implementation = function () {
            try {
                var ret = this.getConnectionInfo();
                log(`[+] Hooked WifiManager.getConnectionInfo(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'WifiManager.getConnectionInfo',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in WifiManager.getConnectionInfo(): ${e.message}`);
                return this.getConnectionInfo();
            }
        };

        WifiManager.getScanResults.overload().implementation = function () {
            try {
                var ret = this.getScanResults();
                log(`[+] Hooked WifiManager.getScanResults(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'WifiManager.getScanResults',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in WifiManager.getScanResults(): ${e.message}`);
                return this.getScanResults();
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking WifiManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking java.net.NetworkInterface.getNetworkInterfaces()
    try {
        var NetworkInterface = Java.use('java.net.NetworkInterface');

        NetworkInterface.getNetworkInterfaces.implementation = function () {
            try {
                var ret = NetworkInterface.getNetworkInterfaces();
                log(`[+] Hooked NetworkInterface.getNetworkInterfaces(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'NetworkInterface.getNetworkInterfaces',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in NetworkInterface.getNetworkInterfaces(): ${e.message}`);
                return NetworkInterface.getNetworkInterfaces();
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking NetworkInterface: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.content.Context.getSystemService(String name)
    try {
        var Context = Java.use('android.content.Context');

        Context.getSystemService.overloads.forEach(function (overload) {
            overload.implementation = function (name) {
                try {
                    var ret = overload.apply(this, arguments);
                    log(`[+] Hooked Context.getSystemService("${name}"): ${ret}`);
                    sendMessage('hook', {
                        'hooked_method': 'Context.getSystemService',
                        'args': { 'name': name },
                        'return_value': ret
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in Context.getSystemService(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking Context.getSystemService: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.os.BatteryManager methods
    try {
        var BatteryManager = Java.use('android.os.BatteryManager');

        BatteryManager.getIntProperty.overloads.forEach(function (overload) {
            overload.implementation = function (id) {
                try {
                    var ret = overload.apply(this, arguments);
                    log(`[+] Hooked BatteryManager.getIntProperty(${id}): ${ret}`);
                    sendMessage('hook', {
                        'hooked_method': 'BatteryManager.getIntProperty',
                        'args': { 'id': id },
                        'return_value': ret
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in BatteryManager.getIntProperty(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
            };
        });

        BatteryManager.isCharging.overload().implementation = function () {
            try {
                var ret = this.isCharging();
                log(`[+] Hooked BatteryManager.isCharging(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'BatteryManager.isCharging',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in BatteryManager.isCharging(): ${e.message}`);
                return this.isCharging();
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking BatteryManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.os.StatFs methods
    try {
        var StatFs = Java.use('android.os.StatFs');

        ['getAvailableBlocksLong', 'getBlockCountLong', 'getBlockSizeLong'].forEach(function (methodName) {
            StatFs[methodName].overload().implementation = function () {
                try {
                    var ret = this[methodName]();
                    log(`[+] Hooked StatFs.${methodName}(): ${ret}`);
                    sendMessage('hook', {
                        'hooked_method': `StatFs.${methodName}`,
                        'return_value': ret
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in StatFs.${methodName}(): ${e.message}`);
                    return this[methodName]();
                }
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking StatFs: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.content.res.Configuration.locale and java.util.Locale.getDefault()
    try {
        var Locale = Java.use('java.util.Locale');

        // Hooking Locale.getDefault()
        Locale.getDefault.overload().implementation = function () {
            try {
                var ret = this.getDefault();
                var value = decodeString(ret.toString());
                log(`[+] Hooked Locale.getDefault(): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'Locale.getDefault',
                    'return_value': value
                });
                return ret;
            } catch (e) {
                log(`[-] Error in Locale.getDefault(): ${e.message}`);
                return this.getDefault();
            }
        };

        // Hooking Configuration.locale
        var Configuration = Java.use('android.content.res.Configuration');

        // Получаем текущий экземпляр Configuration
        var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
        var context = currentApplication.getApplicationContext();
        var resources = context.getResources();
        var configuration = resources.getConfiguration();

        Object.defineProperty(configuration, 'locale', {
            get: function () {
                try {
                    var locale = this.locale.toString();
                    log(`[+] Hooked Configuration.locale: ${locale}`);
                    sendMessage('hook', {
                        'hooked_method': 'Configuration.locale',
                        'value': locale
                    });
                    return this.locale;
                } catch (e) {
                    log(`[-] Error in accessing Configuration.locale: ${e.message}`);
                    return this.locale;
                }
            },
            set: function (newValue) {
                this.locale = newValue;
            }
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking Configuration and Locale: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.hardware.SensorManager.getSensorList(int type)
    try {
        var SensorManager = Java.use('android.hardware.SensorManager');

        SensorManager.getSensorList.overload('int').implementation = function (type) {
            try {
                var ret = this.getSensorList(type);
                log(`[+] Hooked SensorManager.getSensorList(${type}): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'SensorManager.getSensorList',
                    'args': { 'type': type },
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in SensorManager.getSensorList(): ${e.message}`);
                return this.getSensorList(type);
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking SensorManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.view.WindowManager and Display methods
    try {
        var WindowManager = Java.use('android.view.WindowManager');
        var Display = Java.use('android.view.Display');

        // Получаем экземпляр WindowManager
        var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
        var context = currentApplication.getApplicationContext();
        var windowManager = context.getSystemService('window');

        // Hooking getDefaultDisplay()
        windowManager.getDefaultDisplay.overload().implementation = function () {
            try {
                var ret = this.getDefaultDisplay();
                log(`[+] Hooked WindowManager.getDefaultDisplay(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'WindowManager.getDefaultDisplay',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in WindowManager.getDefaultDisplay(): ${e.message}`);
                return this.getDefaultDisplay();
            }
        };

        // Hooking Display.getSize(Point outSize)
        Display.getSize.overload('android.graphics.Point').implementation = function (outSize) {
            try {
                this.getSize(outSize);
                log(`[+] Hooked Display.getSize(): ${outSize.toString()}`);
                sendMessage('hook', {
                    'hooked_method': 'Display.getSize',
                    'args': { 'outSize': outSize.toString() }
                });
            } catch (e) {
                log(`[-] Error in Display.getSize(): ${e.message}`);
                this.getSize(outSize);
            }
        };

        // Hooking Display.getMetrics(DisplayMetrics outMetrics)
        var DisplayMetrics = Java.use('android.util.DisplayMetrics');
        Display.getMetrics.overload('android.util.DisplayMetrics').implementation = function (outMetrics) {
            try {
                this.getMetrics(outMetrics);
                log(`[+] Hooked Display.getMetrics(): ${outMetrics.toString()}`);
                sendMessage('hook', {
                    'hooked_method': 'Display.getMetrics',
                    'args': { 'outMetrics': outMetrics.toString() }
                });
            } catch (e) {
                log(`[-] Error in Display.getMetrics(): ${e.message}`);
                this.getMetrics(outMetrics);
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking WindowManager and Display: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.media.AudioManager methods
    try {
        var AudioManager = Java.use('android.media.AudioManager');

        AudioManager.getStreamVolume.overload('int').implementation = function (streamType) {
            try {
                var ret = this.getStreamVolume(streamType);
                log(`[+] Hooked AudioManager.getStreamVolume(${streamType}): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'AudioManager.getStreamVolume',
                    'args': { 'streamType': streamType },
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in AudioManager.getStreamVolume(): ${e.message}`);
                return this.getStreamVolume(streamType);
            }
        };

        AudioManager.isMusicActive.overload().implementation = function () {
            try {
                var ret = this.isMusicActive();
                log(`[+] Hooked AudioManager.isMusicActive(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'AudioManager.isMusicActive',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in AudioManager.isMusicActive(): ${e.message}`);
                return this.isMusicActive();
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking AudioManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.bluetooth.BluetoothDevice methods
    try {
        var BluetoothDevice = Java.use('android.bluetooth.BluetoothDevice');

        ['getName', 'getBondState'].forEach(function (methodName) {
            BluetoothDevice[methodName].overload().implementation = function () {
                try {
                    var ret = this[methodName]();
                    var value = decodeString(ret);
                    log(`[+] Hooked BluetoothDevice.${methodName}(): ${value}`);
                    sendMessage('hook', {
                        'hooked_method': `BluetoothDevice.${methodName}`,
                        'return_value': value
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in BluetoothDevice.${methodName}(): ${e.message}`);
                    return this[methodName]();
                }
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking BluetoothDevice: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.bluetooth.BluetoothAdapter methods
    try {
        var BluetoothAdapter = Java.use('android.bluetooth.BluetoothAdapter');

        ['getName', 'getBondedDevices'].forEach(function (methodName) {
            BluetoothAdapter[methodName].overload().implementation = function () {
                try {
                    var ret = this[methodName]();
                    var value = decodeString(ret);
                    log(`[+] Hooked BluetoothAdapter.${methodName}(): ${value}`);
                    sendMessage('hook', {
                        'hooked_method': `BluetoothAdapter.${methodName}`,
                        'return_value': value
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in BluetoothAdapter.${methodName}(): ${e.message}`);
                    return this[methodName]();
                }
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking BluetoothAdapter: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.os.Process methods
    try {
        var ProcessClass = Java.use('android.os.Process');

        ['myPid', 'myUid'].forEach(function (methodName) {
            ProcessClass[methodName].overload().implementation = function () {
                try {
                    var ret = this[methodName]();
                    log(`[+] Hooked Process.${methodName}(): ${ret}`);
                    sendMessage('hook', {
                        'hooked_method': `Process.${methodName}`,
                        'return_value': ret
                    });
                    return ret;
                } catch (e) {
                    log(`[-] Error in Process.${methodName}(): ${e.message}`);
                    return this[methodName]();
                }
            };
        });
    } catch (e) {
        var errorMsg = `[-] Error hooking Process methods: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking java.util.TimeZone and Calendar
    try {
        var TimeZone = Java.use('java.util.TimeZone');
        var Calendar = Java.use('java.util.Calendar');

        TimeZone.getDefault.overload().implementation = function () {
            try {
                var ret = this.getDefault();
                var value = decodeString(ret.toString());
                log(`[+] Hooked TimeZone.getDefault(): ${value}`);
                sendMessage('hook', {
                    'hooked_method': 'TimeZone.getDefault',
                    'return_value': value
                });
                return ret;
            } catch (e) {
                log(`[-] Error in TimeZone.getDefault(): ${e.message}`);
                return this.getDefault();
            }
        };

        Calendar.getInstance.overload().implementation = function () {
            try {
                var ret = this.getInstance();
                log(`[+] Hooked Calendar.getInstance(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'Calendar.getInstance',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in Calendar.getInstance(): ${e.message}`);
                return this.getInstance();
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking TimeZone and Calendar: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.content.pm.PackageManager methods
    try {
        var PackageManager = Java.use('android.content.pm.PackageManager');

        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (packageName, flags) {
            try {
                var ret = this.getPackageInfo(packageName, flags);
                log(`[+] Hooked PackageManager.getPackageInfo("${packageName}", ${flags}): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'PackageManager.getPackageInfo',
                    'args': { 'packageName': packageName, 'flags': flags },
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in PackageManager.getPackageInfo(): ${e.message}`);
                return this.getPackageInfo(packageName, flags);
            }
        };

        PackageManager.getApplicationInfo.overload('java.lang.String', 'int').implementation = function (packageName, flags) {
            try {
                var ret = this.getApplicationInfo(packageName, flags);
                log(`[+] Hooked PackageManager.getApplicationInfo("${packageName}", ${flags}): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'PackageManager.getApplicationInfo',
                    'args': { 'packageName': packageName, 'flags': flags },
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in PackageManager.getApplicationInfo(): ${e.message}`);
                return this.getApplicationInfo(packageName, flags);
            }
        };

        PackageManager.hasSystemFeature.overload('java.lang.String').implementation = function (feature) {
            try {
                var ret = this.hasSystemFeature(feature);
                log(`[+] Hooked PackageManager.hasSystemFeature("${feature}"): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'PackageManager.hasSystemFeature',
                    'args': { 'feature': feature },
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in PackageManager.hasSystemFeature(): ${e.message}`);
                return this.hasSystemFeature(feature);
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking PackageManager methods: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.os.UserManager methods
    try {
        var UserManager = Java.use('android.os.UserManager');

        UserManager.getSerialNumberForUser.overload('android.os.UserHandle').implementation = function (user) {
            try {
                var ret = this.getSerialNumberForUser(user);
                log(`[+] Hooked UserManager.getSerialNumberForUser(${user}): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'UserManager.getSerialNumberForUser',
                    'args': { 'user': user.toString() },
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in UserManager.getSerialNumberForUser(): ${e.message}`);
                return this.getSerialNumberForUser(user);
            }
        };

        // Исправление перехвата UserManager.getUserName()
        UserManager.getUserName.overload().implementation = function () {
            try {
                var ret = this.getUserName();
                log(`[+] Hooked UserManager.getUserName(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'UserManager.getUserName',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in UserManager.getUserName(): ${e.message}`);
                return this.getUserName();
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking UserManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking android.content.ClipboardManager.getPrimaryClip()
    try {
        var ClipboardManager = Java.use('android.content.ClipboardManager');

        ClipboardManager.getPrimaryClip.overload().implementation = function () {
            try {
                var ret = this.getPrimaryClip();
                log(`[+] Hooked ClipboardManager.getPrimaryClip(): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'ClipboardManager.getPrimaryClip',
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in ClipboardManager.getPrimaryClip(): ${e.message}`);
                return this.getPrimaryClip();
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking ClipboardManager: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking ContentResolver.query()
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');

        ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            try {
                var ret = this.query(uri, projection, selection, selectionArgs, sortOrder);
                log(`[+] Hooked ContentResolver.query(${uri}, ${projection}, ${selection}, ${selectionArgs}, ${sortOrder}): ${ret}`);
                sendMessage('hook', {
                    'hooked_method': 'ContentResolver.query',
                    'args': {
                        'uri': uri.toString(),
                        'projection': projection,
                        'selection': selection,
                        'selectionArgs': selectionArgs,
                        'sortOrder': sortOrder
                    },
                    'return_value': ret
                });
                return ret;
            } catch (e) {
                log(`[-] Error in ContentResolver.query(): ${e.message}`);
                return this.query(uri, projection, selection, selectionArgs, sortOrder);
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking ContentResolver.query: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Hooking __system_property_get via libc
    try {
        var libc = Process.getModuleByName("libc.so");
        var system_property_get = Module.findExportByName("libc.so", "__system_property_get");

        if (system_property_get) {
            Interceptor.attach(system_property_get, {
                onEnter: function (args) {
                    try {
                        this.key = args[0].readUtf8String();
                        this.value_ptr = args[1];
                        log(`[+] Hooked __system_property_get("${this.key}")`);
                        sendMessage('native_hook', {
                            'hooked_function': '__system_property_get',
                            'args': { 'key': this.key }
                        });
                    } catch (e) {
                        log(`[-] Error in __system_property_get onEnter: ${e.message}`);
                    }
                },
                onLeave: function (retval) {
                    try {
                        var value = this.value_ptr.readUtf8String();
                        var decodedValue = decodeString(value);
                        log(`[+] __system_property_get result for "${this.key}": ${decodedValue}`);
                        sendMessage('native_hook', {
                            'hooked_function': '__system_property_get',
                            'return_value': decodedValue,
                            'args': { 'key': this.key }
                        });
                    } catch (e) {
                        log(`[-] Error in __system_property_get onLeave: ${e.message}`);
                    }
                }
            });
        } else {
            var errorMsg = `[-] __system_property_get not found in libc.so`;
            console.error(errorMsg);
            sendMessage('error', { 'message': errorMsg });
        }
    } catch (e) {
        var errorMsg = `[-] Error hooking __system_property_get: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Расширение перехвата getprop через java.lang.Runtime.exec() и ProcessBuilder
    try {
        var Runtime = Java.use('java.lang.Runtime');
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

        // Перехват всех перегрузок Runtime.exec()
        Runtime.exec.overloads.forEach(function (overload) {
            overload.implementation = function () {
                try {
                    var args = [];
                    for (var i = 0; i < arguments.length; i++) {
                        args.push(arguments[i].toString());
                    }
                    log(`[+] Hooked Runtime.exec(${args.join(', ')})`);
                    sendMessage('hook', {
                        'hooked_method': 'Runtime.exec',
                        'args': args
                    });
                    var ret = overload.apply(this, arguments);
                    return ret;
                } catch (e) {
                    log(`[-] Error in Runtime.exec(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
            };
        });

        // Перехват всех перегрузок ProcessBuilder.command()
        ProcessBuilder.command.overloads.forEach(function (overload) {
            overload.implementation = function () {
                try {
                    var args = [];
                    for (var i = 0; i < arguments.length; i++) {
                        args.push(arguments[i].toString());
                    }
                    log(`[+] Hooked ProcessBuilder.command(${args.join(', ')})`);
                    sendMessage('hook', {
                        'hooked_method': 'ProcessBuilder.command',
                        'args': args
                    });
                    var ret = overload.apply(this, arguments);
                    return ret;
                } catch (e) {
                    log(`[-] Error in ProcessBuilder.command(): ${e.message}`);
                    return overload.apply(this, arguments);
                }
            };
        });

        // Перехват ProcessBuilder.start()
        ProcessBuilder.start.overload().implementation = function () {
            try {
                log(`[+] Hooked ProcessBuilder.start()`);
                sendMessage('hook', {
                    'hooked_method': 'ProcessBuilder.start'
                });
                var ret = this.start();
                return ret;
            } catch (e) {
                log(`[-] Error in ProcessBuilder.start(): ${e.message}`);
                return this.start();
            }
        };
    } catch (e) {
        var errorMsg = `[-] Error hooking getprop via Runtime.exec() and ProcessBuilder: ${e.stack}`;
        console.error(errorMsg);
        sendMessage('error', { 'message': errorMsg });
    }

    // Дополнительные перехваты могут быть добавлены здесь по аналогии
});
