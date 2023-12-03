// Based on https://github.com/iddoeldor/frida-snippets#list-modules
Process.enumerateModulesSync()
    .filter(function(m){ return m['path'].toLowerCase().indexOf('app') !=-1 ; })
    .forEach(function(m) {
        send(JSON.stringify(m, null, '  '));
});