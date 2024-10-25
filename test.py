import frida
import sys
import json
import logging

# Настройка логирования
logging.basicConfig(filename='frida_log.txt', level=logging.INFO, format='%(message)s')

def get_process_info(session):
    script_code = """
    Java.perform(function () {
        var sendMessage = function(type, data) {
            send({
                'type': type,
                'data': data
            });
        };

        // 1. android.os.Build
        try {
            var Build = Java.use('android.os.Build');

            // Перехват свойства VERSION.SDK_INT
            var VERSION = Java.use('android.os.Build$VERSION');
            Object.defineProperty(VERSION, 'SDK_INT', {
                get: function() {
                    var value = this.SDK_INT.value;
                    sendMessage('hook', {
                        'hooked_method': 'android.os.Build.VERSION.SDK_INT',
                        'value': value
                    });
                    return value;
                },
                configurable: true
            });

            // Перехват свойства MODEL
            Object.defineProperty(Build, 'MODEL', {
                get: function() {
                    var value = this.MODEL.value;
                    sendMessage('hook', {
                        'hooked_method': 'android.os.Build.MODEL',
                        'value': value
                    });
                    return value;
                },
                configurable: true
            });

            // Перехват других свойств Build
            var buildFields = ['MANUFACTURER', 'BRAND', 'DEVICE', 'PRODUCT', 'HARDWARE', 'FINGERPRINT', 'SERIAL', 'ID', 'TAGS', 'TYPE', 'USER'];
            buildFields.forEach(function(field) {
                Object.defineProperty(Build, field, {
                    get: function() {
                        var value = this[field].value;
                        sendMessage('hook', {
                            'hooked_method': 'android.os.Build.' + field,
                            'value': value
                        });
                        return value;
                    },
                    configurable: true
                });
            });

            // Перехват метода getSerial()
            Build.getSerial.overload().implementation = function() {
                var ret = this.getSerial();
                sendMessage('hook', {
                    'hooked_method': 'android.os.Build.getSerial()',
                    'return_value': ret
                });
                return ret;
            };

        } catch (e) {
            sendMessage('error', { 'message': 'android.os.Build hook error: ' + e.message });
        }

        // 2. android.os.SystemProperties
        try {
            var SystemProperties = Java.use('android.os.SystemProperties');

            // Перехват метода get(String key)
            SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                var ret = this.get(key);
                sendMessage('hook', {
                    'hooked_method': 'android.os.SystemProperties.get(String key)',
                    'args': key,
                    'return_value': ret
                });
                return ret;
            };

            // Перехват метода get(String key, String def)
            SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                var ret = this.get(key, def);
                sendMessage('hook', {
                    'hooked_method': 'android.os.SystemProperties.get(String key, String def)',
                    'args': { 'key': key, 'def': def },
                    'return_value': ret
                });
                return ret;
            };

            // Перехват метода getInt(String key, int def)
            SystemProperties.getInt.overload('java.lang.String', 'int').implementation = function(key, def) {
                var ret = this.getInt(key, def);
                sendMessage('hook', {
                    'hooked_method': 'android.os.SystemProperties.getInt(String key, int def)',
                    'args': { 'key': key, 'def': def },
                    'return_value': ret
                });
                return ret;
            };

            // Перехват метода getLong(String key, long def)
            SystemProperties.getLong.overload('java.lang.String', 'long').implementation = function(key, def) {
                var ret = this.getLong(key, def);
                sendMessage('hook', {
                    'hooked_method': 'android.os.SystemProperties.getLong(String key, long def)',
                    'args': { 'key': key, 'def': def },
                    'return_value': ret
                });
                return ret;
            };

            // Перехват метода getBoolean(String key, boolean def)
            SystemProperties.getBoolean.overload('java.lang.String', 'boolean').implementation = function(key, def) {
                var ret = this.getBoolean(key, def);
                sendMessage('hook', {
                    'hooked_method': 'android.os.SystemProperties.getBoolean(String key, boolean def)',
                    'args': { 'key': key, 'def': def },
                    'return_value': ret
                });
                return ret;
            };

        } catch (e) {
            sendMessage('error', { 'message': 'android.os.SystemProperties hook error: ' + e.message });
        }

        // 3. android.os.Environment
        try {
            var Environment = Java.use('android.os.Environment');

            // Перехват метода getExternalStorageState()
            Environment.getExternalStorageState.overload().implementation = function() {
                var ret = this.getExternalStorageState();
                sendMessage('hook', {
                    'hooked_method': 'android.os.Environment.getExternalStorageState()',
                    'return_value': ret
                });
                return ret;
            };

            // Перехват метода getExternalStorageDirectory()
            Environment.getExternalStorageDirectory.overload().implementation = function() {
                var ret = this.getExternalStorageDirectory();
                sendMessage('hook', {
                    'hooked_method': 'android.os.Environment.getExternalStorageDirectory()',
                    'return_value': ret
                });
                return ret;
            };

            // Перехват других методов Environment
            var environmentMethods = ['getDataDirectory', 'getDownloadCacheDirectory', 'getRootDirectory'];
            environmentMethods.forEach(function(method) {
                Environment[method].overload().implementation = function() {
                    var ret = this[method]();
                    sendMessage('hook', {
                        'hooked_method': 'android.os.Environment.' + method + '()',
                        'return_value': ret
                    });
                    return ret;
                };
            });

        } catch (e) {
            sendMessage('error', { 'message': 'android.os.Environment hook error: ' + e.message });
        }

        // 4. android.os.Process
        try {
            var Process = Java.use('android.os.Process');

            // Перехват метода myPid()
            Process.myPid.overload().implementation = function() {
                var ret = this.myPid();
                sendMessage('hook', {
                    'hooked_method': 'android.os.Process.myPid()',
                    'return_value': ret
                });
                return ret;
            };

            // Перехват метода myUid()
            Process.myUid.overload().implementation = function() {
                var ret = this.myUid();
                sendMessage('hook', {
                    'hooked_method': 'android.os.Process.myUid()',
                    'return_value': ret
                });
                return ret;
            };

        } catch (e) {
            sendMessage('error', { 'message': 'android.os.Process hook error: ' + e.message });
        }

        // 5. java.lang.System
        try {
            var System = Java.use('java.lang.System');

            // Перехват метода getenv(String name)
            System.getenv.overload('java.lang.String').implementation = function(name) {
                var ret = this.getenv(name);
                sendMessage('hook', {
                    'hooked_method': 'java.lang.System.getenv(String name)',
                    'args': name,
                    'return_value': ret
                });
                return ret;
            };

            // Перехват метода getProperties()
            System.getProperties.overload().implementation = function() {
                var ret = this.getProperties();
                sendMessage('hook', {
                    'hooked_method': 'java.lang.System.getProperties()',
                    'return_value': ret
                });
                return ret;
            };

            // Перехват метода currentTimeMillis()
            System.currentTimeMillis.overload().implementation = function() {
                var ret = this.currentTimeMillis();
                sendMessage('hook', {
                    'hooked_method': 'java.lang.System.currentTimeMillis()',
                    'return_value': ret
                });
                return ret;
            };

        } catch (e) {
            sendMessage('error', { 'message': 'java.lang.System hook error: ' + e.message });
        }

        // 6. java.lang.Runtime
        try {
            var Runtime = Java.use('java.lang.Runtime');

            // Перехват метода getRuntime()
            Runtime.getRuntime.overload().implementation = function() {
                var ret = this.getRuntime();
                sendMessage('hook', {
                    'hooked_method': 'java.lang.Runtime.getRuntime()',
                    'return_value': ret
                });
                return ret;
            };

            // Перехват метода exec(String command)
            Runtime.exec.overload('java.lang.String').implementation = function(command) {
                var ret = this.exec(command);
                sendMessage('hook', {
                    'hooked_method': 'java.lang.Runtime.exec(String command)',
                    'args': command,
                    'return_value': ret
                });
                return ret;
            };

            // Перехват других методов Runtime
            var runtimeMethods = ['availableProcessors', 'freeMemory', 'totalMemory', 'maxMemory'];
            runtimeMethods.forEach(function(method) {
                try {
                    if (Runtime[method].overload) {
                        Runtime[method].overload().implementation = function() {
                            var ret = this[method]();
                            sendMessage('hook', {
                                'hooked_method': 'java.lang.Runtime.' + method + '()',
                                'return_value': ret
                            });
                            return ret;
                        };
                    }
                } catch (e) {
                    sendMessage('error', { 'message': 'java.lang.Runtime.' + method + ' hook error: ' + e.message });
                }
            });

        } catch (e) {
            sendMessage('error', { 'message': 'java.lang.Runtime hook error: ' + e.message });
        }

        // 7. Native API Hooks
        try {
            // Перехват функции uname
            var uname = Module.findExportByName("libc.so", "uname");
            if (uname) {
                Interceptor.attach(uname, {
                    onEnter: function(args) {
                        this.buf_ptr = args[0];
                        sendMessage('native_hook', {
                            'hooked_function': 'uname',
                            'address': ptr(uname).toString(),
                            'args': { 'buf_ptr': this.buf_ptr.toString() }
                        });
                    },
                    onLeave: function(retval) {
                        // Чтение только одного поля для упрощения
                        var sysname = this.buf_ptr.readUtf8String();
                        sendMessage('native_hook', {
                            'hooked_function': 'uname',
                            'return_value': sysname,
                            'address': ptr(uname).toString()
                        });
                    }
                });
            } else {
                sendMessage('error', { 'message': 'Function uname not found in libc.so' });
            }

            // Перехват функции __system_property_get
            var system_property_get = Module.findExportByName("libc.so", "__system_property_get");
            if (system_property_get) {
                Interceptor.attach(system_property_get, {
                    onEnter: function(args) {
                        this.key = args[0].readUtf8String();
                        this.value_ptr = args[1];
                        sendMessage('native_hook', {
                            'hooked_function': '__system_property_get',
                            'address': ptr(system_property_get).toString(),
                            'args': { 'key': this.key, 'value_ptr': this.value_ptr.toString() }
                        });
                    },
                    onLeave: function(retval) {
                        var value = this.value_ptr.readUtf8String();
                        sendMessage('native_hook', {
                            'hooked_function': '__system_property_get',
                            'return_value': value,
                            'address': ptr(system_property_get).toString()
                        });
                    }
                });
            } else {
                sendMessage('error', { 'message': 'Function __system_property_get not found in libc.so' });
            }

            // Перехват функции getenv
            var getenv = Module.findExportByName(null, "getenv");
            if (getenv) {
                Interceptor.attach(getenv, {
                    onEnter: function(args) {
                        this.name = args[0].readUtf8String();
                        sendMessage('native_hook', {
                            'hooked_function': 'getenv',
                            'address': ptr(getenv).toString(),
                            'args': { 'name': this.name }
                        });
                    },
                    onLeave: function(retval) {
                        var value = retval.isNull() ? null : retval.readUtf8String();
                        sendMessage('native_hook', {
                            'hooked_function': 'getenv',
                            'return_value': value,
                            'address': ptr(getenv).toString()
                        });
                    }
                });
            } else {
                sendMessage('error', { 'message': 'Function getenv not found' });
            }

            // Добавьте дополнительные перехватываемые функции по мере необходимости

        } catch (e) {
            sendMessage('error', { 'message': 'Native API Hooks error: ' + e.message });
        }

        // Получение информации о процессе
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var currentProcess = ActivityThread.currentProcessName();
            var Process = Java.use('android.os.Process');
            var pid = Process.myPid();
            var uid = Process.myUid();

            sendMessage('process_info', {
                'process_name': currentProcess,
                'pid': pid,
                'uid': uid
            });
        } catch (e) {
            sendMessage('error', { 'message': 'Process info error: ' + e.message });
        }
    });
    """

    script = session.create_script(script_code)

    # Обработчик сообщений из скрипта
    def on_message(message, data):
        try:
            if message['type'] == 'send':
                payload = message.get('data', {})
                if not isinstance(payload, dict):
                    logging.warning(f"[!] Получено невалидное сообщение: {payload}")
                    print("[!] Получено невалидное сообщение:", payload)
                    return
                msg_type = payload.get('type')
                data_content = payload.get('data', {})

                if msg_type == 'process_info':
                    process_name = data_content.get('process_name', 'Неизвестно')
                    pid = data_content.get('pid', 'Неизвестно')
                    uid = data_content.get('uid', 'Неизвестно')
                    log_message = f"[+] Информация о процессе:\n    Имя процесса: {process_name}\n    PID: {pid}\n    UID: {uid}"
                    logging.info(log_message)
                    print(f"[+] Информация о процессе:")
                    print(f"    Имя процесса: {process_name}")
                    print(f"    PID: {pid}")
                    print(f"    UID: {uid}")

                elif msg_type == 'hook':
                    hooked_method = data_content.get('hooked_method', 'Неизвестно')
                    value = data_content.get('value', 'Неизвестно')
                    address = data_content.get('address', 'Неизвестно')
                    log_message = f"[+] Перехват метода: {hooked_method}\n    Значение: {value}"
                    if address and isinstance(address, str):
                        log_message += f"\n    Адрес: {address}"
                    logging.info(log_message)
                    print(f"[+] Перехват метода: {hooked_method}")
                    print(f"    Значение: {value}")
                    if address and isinstance(address, str):
                        print(f"    Адрес: {address}")

                elif msg_type == 'native_hook':
                    hooked_function = data_content.get('hooked_function', 'Неизвестно')
                    value = data_content.get('return_value', 'Неизвестно')
                    address = data_content.get('address', 'Неизвестно')
                    args = data_content.get('args', {})
                    log_message = f"[+] Перехват нативной функции: {hooked_function}\n    Возвращаемое значение: {value}\n    Адрес: {address}"
                    if args:
                        log_message += f"\n    Аргументы: {json.dumps(args, ensure_ascii=False)}"
                    logging.info(log_message)
                    print(f"[+] Перехват нативной функции: {hooked_function}")
                    if args:
                        print(f"    Аргументы: {json.dumps(args, ensure_ascii=False)}")
                    print(f"    Возвращаемое значение: {value}")
                    print(f"    Адрес: {address}")

                elif msg_type == 'error':
                    error_message = data_content.get('message', 'Неизвестная ошибка')
                    log_message = f"[-] Ошибка из скрипта: {error_message}"
                    logging.error(log_message)
                    print(f"[-] Ошибка из скрипта: {error_message}")

                else:
                    log_message = f"[!] Неизвестный тип сообщения: {payload}"
                    logging.warning(log_message)
                    print("[!] Неизвестный тип сообщения:", payload)

            elif message['type'] == 'error':
                description = message.get('description', 'Нет описания')
                log_message = f"[-] Ошибка в скрипте: {description}"
                logging.error(log_message)
                print(f"[-] Ошибка в скрипте: {description}")

            else:
                log_message = f"[!] Неизвестный тип сообщения: {message}"
                logging.warning(log_message)
                print("[!] Неизвестный тип сообщения:", message)

        except Exception as e:
            log_message = f"[-] Ошибка при обработке сообщения: {e}"
            logging.error(log_message)
            print(f"[-] Ошибка при обработке сообщения: {e}")

    script.on('message', on_message)
    script.load()
    print("[*] Скрипт загружен и выполняется...")

def list_processes():
    import psutil
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def main(target_package):
    try:
        # Подключение к устройству
        device = frida.get_usb_device(timeout=5)
        print(f"[+] Подключено к устройству: {device}")

        # Запуск целевого приложения
        pid = device.spawn([target_package])
        session = device.attach(pid)
        device.resume(pid)
        print(f"[+] Присоединено к процессу '{target_package}' с PID {pid}")

        # Получение и вывод информации о процессе
        processes = list_processes()
        for proc in processes:
            if proc['name'] == target_package or (proc['exe'] and target_package in proc['exe']):
                print(f"[+] Процесс найден:")
                print(f"    Имя процесса: {proc['name']}")
                print(f"    PID: {proc['pid']}")
                print(f"    Путь: {proc['exe']}")
                print(f"    Родительский PID: {proc['ppid']}")
                # Дополнительная информация может быть добавлена по необходимости

        # Загрузка и запуск скрипта
        get_process_info(session)

        print("[*] Ожидание событий. Нажмите Ctrl+C для выхода.")
        sys.stdin.read()

    except frida.ServerNotRunningError:
        print("[-] Frida server не запущен на устройстве.")
    except frida.ProcessNotFoundError:
        print(f"[-] Процесс с пакетом '{target_package}' не найден.")
    except Exception as e:
        print(f"[-] Возникла ошибка: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python frida_full_hook.py <имя_пакета>")
        sys.exit(1)
    target_package = sys.argv[1]
    main(target_package)
