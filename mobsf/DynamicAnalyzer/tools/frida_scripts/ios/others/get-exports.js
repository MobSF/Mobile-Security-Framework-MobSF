// Get Modules and Exports
// Based on: https://github.com/iddoeldor/frida-snippets
// Updated for Frida 17.0.0+
var x = {};
for (const m of Process.enumerateModules()) {
    x[m.name] = m.enumerateExports();
}
console.log(JSON.stringify(x, null, '  '))