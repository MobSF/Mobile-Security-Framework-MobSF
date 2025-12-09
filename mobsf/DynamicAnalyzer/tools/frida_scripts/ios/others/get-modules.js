// Based on https://github.com/iddoeldor/frida-snippets#list-modules
// Updated for Frida 17.0.0+ compatibility
Process.enumerateModules()
    .filter(function(m){ return m['path'].toLowerCase().indexOf('app') !=-1 ; })
    .forEach(function(m) {
        send(JSON.stringify(m, null, '  '));
});