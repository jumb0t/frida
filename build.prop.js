// frida_hook_build_prop.js

// Объект для отслеживания файловых дескрипторов и указателей FILE*, связанных с build.prop
var trackedFiles = {};

// Функция для перехвата функций open и open64
function hookOpenFunctions() {
    var openFuncs = ['open', 'open64'];
    openFuncs.forEach(function(funcName) {
        var addr = Module.findExportByName(null, funcName);
        if (addr) {
            console.log('[*] Found ' + funcName + ' at ' + addr);
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    this.path = Memory.readUtf8String(args[0]);
                    this.flags = args[1];
                    console.log('[File IO Hook] ' + funcName + ' called with path: ' + this.path);

                    if (this.path === '/system/build.prop') {
                        this.shouldTrack = true;
                    } else {
                        this.shouldTrack = false;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldTrack) {
                        var fd = retval.toInt32();
                        trackedFiles[fd] = {
                            path: this.path,
                            position: 0 // Инициализируем позицию для отслеживания
                        };
                        console.log('[File IO Hook] Tracking fd: ' + fd + ' for path: ' + this.path);
                    }
                }
            });
        } else {
            console.log('[-] Failed to find ' + funcName + ' function.');
        }
    });
}

// Функция для перехвата функции read
function hookRead() {
    var readAddr = Module.findExportByName(null, 'read');
    if (readAddr) {
        console.log('[*] Found read at ' + readAddr);
        Interceptor.attach(readAddr, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2].toInt32();

                if (trackedFiles.hasOwnProperty(this.fd)) {
                    this.shouldModify = true;
                    console.log('[File IO Hook] read called on tracked fd: ' + this.fd + ', count: ' + this.count);
                } else {
                    this.shouldModify = false;
                }
            },
            onLeave: function(retval) {
                if (this.shouldModify && retval.toInt32() > 0) {
                    var bytesRead = retval.toInt32();
                    var originalData = Memory.readUtf8String(this.buf, bytesRead);

                    // Здесь вы можете изменить данные по своему усмотрению
                    var modifiedData = originalData.replace(/ro\.hardware=.*/g, 'ro.hardware=test_value');
                    modifiedData = modifiedData.replace(/ro\.boot\.hardware=.*/g, 'ro.boot.hardware=test_value');

                    // Обновляем буфер с измененными данными
                    Memory.writeUtf8String(this.buf, modifiedData);

                    console.log('[File IO Hook] Modified data read from fd: ' + this.fd);
                }
            }
        });
    } else {
        console.log('[-] Failed to find read function.');
    }
}

// Функция для перехвата функции close
function hookClose() {
    var closeAddr = Module.findExportByName(null, 'close');
    if (closeAddr) {
        console.log('[*] Found close at ' + closeAddr);
        Interceptor.attach(closeAddr, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();

                if (trackedFiles.hasOwnProperty(this.fd)) {
                    console.log('[File IO Hook] close called on tracked fd: ' + this.fd);
                    delete trackedFiles[this.fd];
                }
            }
        });
    } else {
        console.log('[-] Failed to find close function.');
    }
}

// Функция для перехвата функции fopen
function hookFopen() {
    var fopenAddr = Module.findExportByName(null, 'fopen');
    if (fopenAddr) {
        console.log('[*] Found fopen at ' + fopenAddr);
        Interceptor.attach(fopenAddr, {
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
                this.mode = Memory.readUtf8String(args[1]);
                console.log('[File IO Hook] fopen called with path: ' + this.path + ', mode: ' + this.mode);

                if (this.path === '/system/build.prop') {
                    this.shouldTrack = true;
                } else {
                    this.shouldTrack = false;
                }
            },
            onLeave: function(retval) {
                if (this.shouldTrack && !retval.isNull()) {
                    var filePtr = retval.toUInt32();
                    trackedFiles[filePtr] = {
                        path: this.path,
                        position: 0 // Инициализируем позицию для отслеживания
                    };
                    console.log('[File IO Hook] Tracking FILE*: ' + filePtr + ' for path: ' + this.path);
                }
            }
        });
    } else {
        console.log('[-] Failed to find fopen function.');
    }
}

// Функция для перехвата функции fread
function hookFread() {
    var freadAddr = Module.findExportByName(null, 'fread');
    if (freadAddr) {
        console.log('[*] Found fread at ' + freadAddr);
        Interceptor.attach(freadAddr, {
            onEnter: function(args) {
                this.ptr = args[0];
                this.size = args[1].toInt32();
                this.nmemb = args[2].toInt32();
                this.stream = args[3].toUInt32();

                if (trackedFiles.hasOwnProperty(this.stream)) {
                    this.shouldModify = true;
                    console.log('[File IO Hook] fread called on tracked FILE*: ' + this.stream);
                } else {
                    this.shouldModify = false;
                }
            },
            onLeave: function(retval) {
                if (this.shouldModify && retval.toInt32() > 0) {
                    var bytesRead = retval.toInt32() * this.size;
                    var originalData = Memory.readUtf8String(this.ptr, bytesRead);

                    // Здесь вы можете изменить данные по своему усмотрению
                    var modifiedData = originalData.replace(/ro\.hardware=.*/g, 'ro.hardware=test_value');
                    modifiedData = modifiedData.replace(/ro\.boot\.hardware=.*/g, 'ro.boot.hardware=test_value');

                    // Обновляем буфер с измененными данными
                    Memory.writeUtf8String(this.ptr, modifiedData);

                    console.log('[File IO Hook] Modified data read from FILE*: ' + this.stream);
                }
            }
        });
    } else {
        console.log('[-] Failed to find fread function.');
    }
}

// Функция для перехвата функции fclose
function hookFclose() {
    var fcloseAddr = Module.findExportByName(null, 'fclose');
    if (fcloseAddr) {
        console.log('[*] Found fclose at ' + fcloseAddr);
        Interceptor.attach(fcloseAddr, {
            onEnter: function(args) {
                this.stream = args[0].toUInt32();

                if (trackedFiles.hasOwnProperty(this.stream)) {
                    console.log('[File IO Hook] fclose called on tracked FILE*: ' + this.stream);
                    delete trackedFiles[this.stream];
                }
            }
        });
    } else {
        console.log('[-] Failed to find fclose function.');
    }
}

// Инициация всех перехватов
function hookAll() {
    hookOpenFunctions();
    hookRead();
    hookClose();
    hookFopen();
    hookFread();
    hookFclose();
}

// Основная точка входа
hookAll();
