send("Tracing SQLite Queries");

function hookSql(func, position, pretext) {
    try {
        const libsqlite3 = Process.getModuleByName('libsqlite3.dylib');
        var to_hook = libsqlite3.getExportByName(func);
        Interceptor.attach(to_hook, {
            onEnter: function(args) {
                send(JSON.stringify({'[MBSFDUMP] sql': pretext + args[position].readCString()}));
            },
            onLeave: function(retval) {}
        });
    } catch (e) {}
}
try {
    hookSql('sqlite3_open', 0, 'OPEN: ');
} catch(err) {}
try {
    hookSql('sqlite3_prepare_v2', 1, 'PREPARED: ');
} catch(err) {}
try {
    hookSql('sqlite3_bind_text', 2, 'BIND TEXT: ');
} catch(err) {}
try {
    hookSql('sqlite3_bind_text16', 2, 'BIND TEXT: ');
} catch(err) {}
