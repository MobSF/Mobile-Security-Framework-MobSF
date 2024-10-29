send("Tracing SQLite Queries");

function hookSql(func, position, pretext) {
    var to_hook = Module.findExportByName('libsqlite3.dylib', func);
    Interceptor.attach(to_hook, {
        onEnter: function(args) {
            send(JSON.stringify({'[MBSFDUMP] sql': pretext + args[position].readCString()}));
        },
        onLeave: function(retval) {}
    });
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
