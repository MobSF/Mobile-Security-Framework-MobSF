// Get Modules and Exports
// Based on: https://github.com/iddoeldor/frida-snippets
var x = {};
Process.enumerateModulesSync().forEach(function(m){
    x[m.name] = Module.enumerateExportsSync(m.name)
});
console.log(JSON.stringify(x, null, '  '))