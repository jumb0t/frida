// frida_hook_system_properties.js

// Функция для вывода информации о процессе
function logProcessInfo() {
    console.log('[*] Process Name: ' + (Process.name || 'undefined'));
    console.log('[*] Process ID (PID): ' + Process.id);
}

// =======================================
// Перехват нативных функций
// =======================================

// Перехват функции __system_property_get
function hookSystemPropertyGet() {
    var libname = null; // Поиск во всех модулях
    var property_get = Module.findExportByName(libname, '__system_property_get');

    if (property_get !== null) {
        console.log('[*] Found __system_property_get at ' + property_get);

        Interceptor.attach(property_get, {
            onEnter: function(args) {
                this.key = Memory.readUtf8String(args[0]);
                console.log('[Native Hook] __system_property_get called with key: ' + this.key);

                // Проверяем, если ключ соответствует целевым свойствам
                if (this.key === 'ro.hardware' || this.key === 'ro.boot.hardware') {
                    this.shouldModify = true;
                    this.valuePtr = args[1];
                } else {
                    this.shouldModify = false;
                }
            },
            onLeave: function(retval) {
                if (this.shouldModify) {
                    var newValue = 'test_value_native';
                    Memory.writeUtf8String(this.valuePtr, newValue);
                    retval.replace(newValue.length);
                    console.log('[Native Hook] __system_property_get replaced value for key: ' + this.key);
                }
            }
        });
        console.log('[+] Hooked __system_property_get successfully.');
    } else {
        console.log('[-] Failed to find __system_property_get function.');
    }
}

// Перехват функции property_get из libcutils.so
function hookPropertyGetFromLibcutils() {
    var libcutils = Process.findModuleByName('libcutils.so');
    if (libcutils) {
        console.log('[*] Found module libcutils.so at ' + libcutils.base);

        var property_get = Module.findExportByName('libcutils.so', 'property_get');

        if (property_get) {
            console.log('[*] Found property_get at ' + property_get + ' via exports');
        } else {
            console.log('[-] Failed to find property_get by exports, trying symbols...');

            var symbols = Module.enumerateSymbolsSync('libcutils.so');
            for (var i = 0; i < symbols.length; i++) {
                if (symbols[i].name === 'property_get') {
                    property_get = symbols[i].address;
                    console.log('[*] Found property_get at ' + property_get + ' via symbols');
                    break;
                }
            }
        }

        if (property_get) {
            console.log('[*] Attempting to attach to property_get at ' + property_get);
            Interceptor.attach(property_get, {
                onEnter: function(args) {
                    this.key = Memory.readUtf8String(args[0]);
                    this.valuePtr = args[1];
                    console.log('[Native Hook] property_get called with key: ' + this.key);

                    if (this.key === 'ro.hardware' || this.key === 'ro.boot.hardware') {
                        this.shouldModify = true;
                    } else {
                        this.shouldModify = false;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldModify) {
                        var newValue = 'test_value_native';
                        Memory.writeUtf8String(this.valuePtr, newValue);
                        retval.replace(newValue.length);
                        console.log('[Native Hook] property_get replaced value for key: ' + this.key);
                    }
                }
            });
            console.log('[+] Hooked property_get from libcutils.so successfully.');
        } else {
            console.log('[-] Failed to find property_get function in libcutils.so.');
        }
    } else {
        console.log('[-] Failed to find libcutils.so module.');
    }
}

// =======================================
// Перехват Java методов
// =======================================

// Перехват методов SystemProperties.get
function hookJavaSystemProperties() {
    Java.perform(function() {
        try {
            var SystemProperties = Java.use('android.os.SystemProperties');
            console.log('[*] Hooking android.os.SystemProperties');

            // Перехват перегрузки get(String key)
            SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                console.log('[Java Hook] SystemProperties.get(String) called with key: ' + key);
                if (key === 'ro.hardware' || key === 'ro.boot.hardware') {
                    console.log('[Java Hook] SystemProperties.get(String) replacing value for key: ' + key);
                    return 'test_value_java';
                }
                return this.get(key);
            };

            // Перехват перегрузки get(String key, String def)
            SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                console.log('[Java Hook] SystemProperties.get(String, String) called with key: ' + key + ', def: ' + def);
                if (key === 'ro.hardware' || key === 'ro.boot.hardware') {
                    console.log('[Java Hook] SystemProperties.get(String, String) replacing value for key: ' + key);
                    return 'test_value_java';
                }
                return this.get(key, def);
            };

            console.log('[+] Hooked SystemProperties.get successfully.');
        } catch (e) {
            console.log('[-] Error hooking SystemProperties: ' + e.message);
            console.log('[-] SystemProperties class not available yet, retrying...');
            setTimeout(hookJavaSystemProperties, 1000); // Попробовать снова через 1 секунду
        }
    });
}

// Перехват методов System.getProperty
function hookJavaSystemGetProperty() {
    Java.perform(function() {
        try {
            var SystemClass = Java.use('java.lang.System');
            console.log('[*] Hooking java.lang.System');

            // Перехват перегрузки getProperty(String key)
            SystemClass.getProperty.overload('java.lang.String').implementation = function(key) {
                console.log('[Java Hook] System.getProperty(String) called with key: ' + key);
                if (key === 'ro.hardware' || key === 'ro.boot.hardware') {
                    console.log('[Java Hook] System.getProperty(String) replacing value for key: ' + key);
                    return 'test_value_java';
                }
                return this.getProperty(key);
            };

            // Перехват перегрузки getProperty(String key, String def)
            SystemClass.getProperty.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                console.log('[Java Hook] System.getProperty(String, String) called with key: ' + key + ', def: ' + def);
                if (key === 'ro.hardware' || key === 'ro.boot.hardware') {
                    console.log('[Java Hook] System.getProperty(String, String) replacing value for key: ' + key);
                    return 'test_value_java';
                }
                return this.getProperty(key, def);
            };

            console.log('[+] Hooked System.getProperty successfully.');
        } catch (e) {
            console.log('[-] Error hooking System.getProperty: ' + e.message);
            console.log('[-] System class not available yet, retrying...');
            setTimeout(hookJavaSystemGetProperty, 1000); // Попробовать снова через 1 секунду
        }
    });
}

// =======================================
// Перехват функций файлового ввода-вывода
// =======================================

// Перехват функций open и open64
function hookOpenFunctions() {
    var openFuncs = ['open', 'open64'];
    openFuncs.forEach(function(funcName) {
        var addr = Module.findExportByName(null, funcName);
        if (addr) {
            console.log('[*] Found ' + funcName + ' at ' + addr);
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    this.path = path;
                    console.log('[File IO Hook] ' + funcName + ' called with path: ' + path);
                },
                onLeave: function(retval) {
                    if (this.path && (this.path === '/system/build.prop' || this.path === '/proc/version')) {
                        this.fd = retval.toInt32();
                        console.log('[File IO Hook] ' + funcName + ' returned fd: ' + this.fd);
                    }
                }
            });
        } else {
            console.log('[-] Failed to find ' + funcName + ' function.');
        }
    });
}

// Перехват функции fopen
function hookFopen() {
    var fopenAddr = Module.findExportByName(null, 'fopen');
    if (fopenAddr) {
        console.log('[*] Found fopen at ' + fopenAddr);
        Interceptor.attach(fopenAddr, {
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
                this.mode = Memory.readUtf8String(args[1]);
                console.log('[File IO Hook] fopen called with path: ' + this.path + ', mode: ' + this.mode);
            },
            onLeave: function(retval) {
                if (this.path && (this.path === '/system/build.prop' || this.path === '/proc/version')) {
                    this.file = retval;
                    console.log('[File IO Hook] fopen returned FILE*: ' + this.file);
                }
            }
        });
    } else {
        console.log('[-] Failed to find fopen function.');
    }
}

// Перехват функции read и pread
function hookReadFunctions() {
    var readFuncs = ['read', 'pread'];
    readFuncs.forEach(function(funcName) {
        var addr = Module.findExportByName(null, funcName);
        if (addr) {
            console.log('[*] Found ' + funcName + ' at ' + addr);
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    this.fd = args[0].toInt32();
                    this.buffer = args[1];
                    this.count = args[2].toInt32();
                    // Проверяем, соответствует ли fd целевым файлам
                    // Здесь необходимо хранить список fd, соответствующих /system/build.prop и т.д.
                },
                onLeave: function(retval) {
                    // Если fd соответствует целевым файлам, можно изменить содержимое буфера
                    // Однако это требует дополнительного отслеживания fd
                    // Для упрощения мы просто логируем вызов
                    console.log('[File IO Hook] ' + funcName + ' called with fd: ' + this.fd + ', count: ' + this.count);
                }
            });
        } else {
            console.log('[-] Failed to find ' + funcName + ' function.');
        }
    });
}

// Перехват функции fread
function hookFread() {
    var freadAddr = Module.findExportByName(null, 'fread');
    if (freadAddr) {
        console.log('[*] Found fread at ' + freadAddr);
        Interceptor.attach(freadAddr, {
            onEnter: function(args) {
                this.ptr = args[0];
                this.size = args[1].toInt32();
                this.count = args[2].toInt32();
                this.stream = args[3];
                console.log('[File IO Hook] fread called with ptr: ' + this.ptr + ', size: ' + this.size + ', count: ' + this.count + ', stream: ' + this.stream);
            },
            onLeave: function(retval) {
                console.log('[File IO Hook] fread returned ' + retval.toInt32() + ' items.');
                // Здесь можно изменить данные, читаемые из файла, если необходимо
            }
        });
    } else {
        console.log('[-] Failed to find fread function.');
    }
}

// =======================================
// Перехват через JNI (опционально)
// =======================================

// Перехват функций, используемых через JNI для доступа к системным свойствам
// Это требует знания конкретных функций, используемых приложением. Здесь приведен пример перехвата JNI вызова property_get через JNI

function hookJNIPropertyGet() {
    // Предполагаем, что приложение использует функцию property_get из libcutils.so через JNI
    var property_get = Module.findExportByName('libcutils.so', 'property_get');
    if (property_get) {
        console.log('[*] Found JNI property_get at ' + property_get);
        Interceptor.attach(property_get, {
            onEnter: function(args) {
                this.key = Memory.readUtf8String(args[0]);
                this.valuePtr = args[1];
                console.log('[JNI Hook] property_get called with key: ' + this.key);
                if (this.key === 'ro.hardware' || this.key === 'ro.boot.hardware') {
                    this.shouldModify = true;
                } else {
                    this.shouldModify = false;
                }
            },
            onLeave: function(retval) {
                if (this.shouldModify) {
                    var newValue = 'test_value_jni';
                    Memory.writeUtf8String(this.valuePtr, newValue);
                    retval.replace(newValue.length);
                    console.log('[JNI Hook] property_get replaced value for key: ' + this.key);
                }
            }
        });
    } else {
        console.log('[-] Failed to find JNI property_get function in libcutils.so.');
    }
}

// =======================================
// Функция для трассировки всех вызовов SystemProperties.get (опционально)
// =======================================

function traceSystemPropertiesUsage() {
    Java.perform(function() {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overloads.forEach(function(overload) {
            overload.implementation = function() {
                var args = [].slice.call(arguments);
                console.log('[Trace] SystemProperties.get called with args: ' + args);
                return overload.apply(this, arguments);
            };
        });
    });
}

// =======================================
// Инициация всех перехватов
// =======================================

function hookAll() {
    // Перехват нативных функций
    hookSystemPropertyGet();
    hookPropertyGetFromLibcutils();

    // Перехват Java методов
    hookJavaSystemProperties();
    hookJavaSystemGetProperty();

    // Перехват функций файлового ввода-вывода
    hookOpenFunctions();
    hookFopen();
    hookReadFunctions();
    hookFread();

    // Перехват через JNI (опционально)
    hookJNIPropertyGet();

    // Опционально, включить трассировку
    // traceSystemPropertiesUsage();
}

// =======================================
// Основная точка входа
// =======================================

// Логируем информацию о процессе
logProcessInfo();

// Проверяем доступность Java VM
if (Java.available) {
    console.log('[*] Java VM is available.');
    hookAll();
} else {
    console.log('[-] Java VM not available, retrying...');
    var javaInterval = setInterval(function() {
        if (Java.available) {
            console.log('[*] Java VM is now available.');
            hookAll();
            clearInterval(javaInterval);
        } else {
            console.log('[-] Java VM still not available...');
        }
    }, 1000);
}
