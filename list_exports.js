// list_exports.js
'use strict';

Module.enumerateExports('libc.so', {
    onMatch: function(exp) {
        console.log(exp.name);
    },
    onComplete: function() {}
});
