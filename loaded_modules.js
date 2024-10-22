Java.perform(function () {
    var modules = Process.enumerateModules();
    modules.forEach(function(module) {
        console.log("Module: " + module.name + ", Base Address: " + module.base);
    });
});
