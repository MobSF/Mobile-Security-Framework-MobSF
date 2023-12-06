
/**
It should be launch earlier in order to be aware of a maximun 
quantity of file descriptors.


@author @FrenchYeti
*/
Java.perform(function () {

    // ============= Config
    var CONFIG = {
        // if TRUE enable data dump 
        printEnable: true,
        // if TRUE enable libc.so open/read/write hook
        printLibc: false,
        // if TRUE print the stack trace for each hook
        printStackTrace: false,
        // to filter the file path whose data want to be dumped in ASCII 
        dump_ascii_If_Path_contains: [".log", ".xml", ".prop"],
        // to filter the file path whose data want to be NOT dumped in hexdump (useful for big chunk and excessive reads) 
        dump_hex_If_Path_NOT_contains: [".png", "/proc/self/task", "/system/lib", "base.apk", "cacert"],
        // to filter the file path whose data want to be NOT dumped fron libc read/write (useful for big chunk and excessive reads) 
        dump_raw_If_Path_NOT_contains: [".png", "/proc/self/task", "/system/lib", "base.apk", "cacert"]
    }

    // =============  Keep a trace of file descriptor, path, and so
    var TraceFD = {};
    var TraceFS = {};
    var TraceFile = {};
    var TraceSysFD = {};


    // ============= Get classes
    var CLS = {
        File: Java.use("java.io.File"),
        FileInputStream: Java.use("java.io.FileInputStream"),
        FileOutputStream: Java.use("java.io.FileOutputStream"),
        String: Java.use("java.lang.String"),
        FileChannel: Java.use("java.nio.channels.FileChannel"),
        FileDescriptor: Java.use("java.io.FileDescriptor"),
        Thread: Java.use("java.lang.Thread"),
        StackTraceElement: Java.use("java.lang.StackTraceElement"),
        AndroidDbSQLite: Java.use("android.database.sqlite.SQLiteDatabase")
    };
    var File = {
        new: [
            CLS.File.$init.overload("java.io.File", "java.lang.String"),
            CLS.File.$init.overload("java.lang.String"),
            CLS.File.$init.overload("java.lang.String", "java.lang.String"),
            CLS.File.$init.overload("java.net.URI"),
        ]
    };
    var FileInputStream = {
        new: [
            CLS.FileInputStream.$init.overload("java.io.File"),
            CLS.FileInputStream.$init.overload("java.io.FileDescriptor"),
            CLS.FileInputStream.$init.overload("java.lang.String"),
        ],
        read: [
            CLS.FileInputStream.read.overload(),
            CLS.FileInputStream.read.overload("[B"),
            CLS.FileInputStream.read.overload("[B", "int", "int"),
        ],
    };
    var FileOuputStream = {
        new: [
            CLS.FileOutputStream.$init.overload("java.io.File"),
            CLS.FileOutputStream.$init.overload("java.io.File", "boolean"),
            CLS.FileOutputStream.$init.overload("java.io.FileDescriptor"),
            CLS.FileOutputStream.$init.overload("java.lang.String"),
            CLS.FileOutputStream.$init.overload("java.lang.String", "boolean")
        ],
        write: [
            CLS.FileOutputStream.write.overload("[B"),
            CLS.FileOutputStream.write.overload("int"),
            CLS.FileOutputStream.write.overload("[B", "int", "int"),
        ],
    };



    // ============= Hook implementation

    File.new[1].implementation = function (a0) {
        prettyLog("[Java::File.new.1] New file : " + a0);

        var ret = File.new[1].call(this, a0);
        var f = Java.cast(this, CLS.File);
        TraceFile["f" + this.hashCode()] = a0;


        return ret;
    }
    File.new[2].implementation = function (a0, a1) {
        prettyLog("[Java::File.read.2] New file : " + a0 + "/" + a1);

        var ret = File.new[2].call(this, a0, a1);;
        var f = Java.cast(this, CLS.File);
        TraceFile["f" + this.hashCode()] = a0 + "/" + a1;

        return ret;
    }


    FileInputStream.new[0].implementation = function (a0) {
        var file = Java.cast(a0, CLS.File);
        var fname = TraceFile["f" + file.hashCode()];

        if (fname == null) {
            var p = file.getAbsolutePath();
            if (p !== null)
                fname = TraceFile["f" + file.hashCode()] = p;
        }
        if (fname == null)
            fname = "[unknow]"

        prettyLog("[Java::FileInputStream.new.0] New input stream from file (" + fname + "): ");

        var fis = FileInputStream.new[0].call(this, a0)
        var f = Java.cast(this, CLS.FileInputStream);

        TraceFS["fd" + this.hashCode()] = fname;

        var fd = Java.cast(this.getFD(), CLS.FileDescriptor);

        TraceFD["fd" + fd.hashCode()] = fname;

        return fis;
    }



    FileInputStream.read[1].implementation = function (a0) {
        var fname = TraceFS["fd" + this.hashCode()];
        var fd = null;
        if (fname == null) {
            fd = Java.cast(this.getFD(), CLS.FileDescriptor);
            fname = TraceFD["fd" + fd.hashCode()]
        }
        if (fname == null)
            fname = "[unknow]";

        var b = Java.array('byte', a0);

        prettyLog("[Java::FileInputStream.read.1] Read from file,offset (" + fname + "," + a0 + "):\n" +
            prettyPrint(fname, b));

        return FileInputStream.read[1].call(this, a0);
    }
    FileInputStream.read[2].implementation = function (a0, a1, a2) {
        var fname = TraceFS["fd" + this.hashCode()];
        var fd = null;
        if (fname == null) {
            fd = Java.cast(this.getFD(), CLS.FileDescriptor);
            fname = TraceFD["fd" + fd.hashCode()]
        }
        if (fname == null)
            fname = "[unknow]";

        var b = Java.array('byte', a0);

        prettyLog("[Java::FileInputStream.read.2] Read from file,offset,len (" + fname + "," + a1 + "," + a2 + ")\n" +
            prettyPrint(fname, b));

        return FileInputStream.read[2].call(this, a0, a1, a2);
    }



    // =============== File Output Stream ============



    FileOuputStream.new[0].implementation = function (a0) {
        var file = Java.cast(a0, CLS.File);
        var fname = TraceFile["f" + file.hashCode()];

        if (fname == null)
            fname = "[unknow]<File:" + file.hashCode() + ">";


        prettyLog("[Java::FileOuputStream.new.0] New output stream to file (" + fname + "): ");

        var fis = FileOuputStream.new[0].call(this, a0);

        TraceFS["fd" + this.hashCode()] = fname;

        var fd = Java.cast(this.getFD(), CLS.FileDescriptor);
        TraceFD["fd" + fd.hashCode()] = fname;

        return fis;
    }

    FileOuputStream.new[1].implementation = function (a0) {
        var file = Java.cast(a0, CLS.File);
        var fname = TraceFile["f" + file.hashCode()];

        if (fname == null)
            fname = "[unknow]";


        prettyLog("[Java::FileOuputStream.new.1] New output stream to file (" + fname + "): \n");

        var fis = FileOuputStream.new[1].call(this, a0);

        TraceFS["fd" + this.hashCode()] = fname;

        var fd = Java.cast(this.getFD(), CLS.FileDescriptor);

        TraceFD["fd" + fd.hashCode()] = fname;

        return fis;
    }

    FileOuputStream.new[2].implementation = function (a0) {
        var fd = Java.cast(a0, CLS.FileDescriptor);
        var fname = TraceFD["fd" + fd.hashCode()];

        if (fname == null)
            fname = "[unknow]";


        prettyLog("[Java::FileOuputStream.new.2] New output stream to FileDescriptor (" + fname + "): \n");
        var fis = FileOuputStream.new[1].call(this, a0)

        TraceFS["fd" + this.hashCode()] = fname;

        return fis;
    }
    FileOuputStream.new[3].implementation = function (a0) {
        prettyLog("[Java::FileOuputStream.new.3] New output stream to file (str=" + a0 + "): \n");

        var fis = FileOuputStream.new[1].call(this, a0)

        TraceFS["fd" + this.hashCode()] = a0;
        var fd = Java.cast(this.getFD(), CLS.FileDescriptor);
        TraceFD["fd" + fd.hashCode()] = a0;

        return fis;
    }
    FileOuputStream.new[4].implementation = function (a0) {
        prettyLog("[Java::FileOuputStream.new.4] New output stream to file (str=" + a0 + ",bool): \n");

        var fis = FileOuputStream.new[1].call(this, a0)
        TraceFS["fd" + this.hashCode()] = a0;
        var fd = Java.cast(this.getFD(), CLS.FileDescriptor);
        TraceFD["fd" + fd.hashCode()] = a0;

        return fis;
    }



    FileOuputStream.write[0].implementation = function (a0) {
        var fname = TraceFS["fd" + this.hashCode()];
        var fd = null;

        if (fname == null) {
            fd = Java.cast(this.getFD(), CLS.FileDescriptor);
            fname = TraceFD["fd" + fd.hashCode()]
        }
        if (fname == null)
            fname = "[unknow]";

        prettyLog("[Java::FileOuputStream.write.0] Write byte array (" + fname + "):\n" +
            prettyPrint(fname, a0));

        return FileOuputStream.write[0].call(this, a0);
    }
    FileOuputStream.write[1].implementation = function (a0) {

        var fname = TraceFS["fd" + this.hashCode()];
        var fd = null;
        if (fname == null) {
            fd = Java.cast(this.getFD(), CLS.FileDescriptor);
            fname = TraceFD["fd" + fd.hashCode()]
        }
        if (fname == null)
            fname = "[unknow]";

        prettyLog("[Java::FileOuputStream.write.1] Write int  (" + fname + "): " + a0);


        return FileOuputStream.write[1].call(this, a0);
    }
    FileOuputStream.write[2].implementation = function (a0, a1, a2) {

        var fname = TraceFS["fd" + this.hashCode()];
        var fd = null;
        if (fname == null) {
            fd = Java.cast(this.getFD(), CLS.FileDescriptor);
            fname = TraceFD["fd" + fd.hashCode()]
            if (fname == null)
                fname = "[unknow], fd=" + this.hashCode();
        }

        prettyLog("[Java::FileOuputStream.write.2] Write " + a2 + " bytes from " + a1 + "  (" + fname + "):\n" +
            prettyPrint(fname, a0));

        return FileOuputStream.write[2].call(this, a0, a1, a2);
    }

    // native hooks    
    Interceptor.attach(
        Module.findExportByName("libc.so", "read"), {
            // fd, buff, len
            onEnter: function (args) {
                if (CONFIG.printLibc === true) {
                    var bfr = args[1],
                        sz = args[2].toInt32();
                    var path = (TraceSysFD["fd-" + args[0].toInt32()] != null) ? TraceSysFD["fd-" + args[0].toInt32()] : "[unknow path]";

                    prettyLog("[Libc::read] Read FD (" + path + "," + bfr + "," + sz + ")\n" +
                        rawPrint(path, Memory.readByteArray(bfr, sz)));
                }
            },
            onLeave: function (ret) {

            }
        }
    );

    Interceptor.attach(
        Module.findExportByName("libc.so", "open"), {
            // path, flags, mode
            onEnter: function (args) {
                this.path = Memory.readCString(args[0]);
            },
            onLeave: function (ret) {
                TraceSysFD["fd-" + ret.toInt32()] = this.path;
                if (CONFIG.printLibc === true)
                    prettyLog("[Libc::open] Open file '" + this.path + "' (fd: " + ret.toInt32() + ")");
            }
        }
    );


    Interceptor.attach(
        Module.findExportByName("libc.so", "write"), {
            // fd, buff, count
            onEnter: function (args) {
                if (CONFIG.printLibc === true) {
                    var bfr = args[1],
                        sz = args[2].toInt32();
                    var path = (TraceSysFD["fd-" + args[0].toInt32()] != null) ? TraceSysFD["fd-" + args[0].toInt32()] : "[unknow path]";

                    prettyLog("[Libc::write] Write FD (" + path + "," + bfr + "," + sz + ")\n" +
                        rawPrint(path, Memory.readByteArray(bfr, sz)));
                }
            },
            onLeave: function (ret) {

            }
        }
    );



    // helper functions
    function prettyLog(str) {
        send("---------------------------\n" + str);
        if (CONFIG.printStackTrace === true) {
            printStackTrace();
        }
    }

    function prettyPrint(path, buffer) {
        if (CONFIG.printEnable === false) return "";

        if (contains(path, CONFIG.dump_ascii_If_Path_contains)) {
            return b2s(buffer);
        } else if (!contains(path, CONFIG.dump_hex_If_Path_NOT_contains)) {
            return hexdump(b2s(buffer));
        }
        return "[dump skipped by config]";
    }

    function rawPrint(path, buffer) {
        if (CONFIG.printEnable === false) return "";

        if (!contains(path, CONFIG.dump_raw_If_Path_NOT_contains)) {
            return hexdump(buffer);
        }
        return "[dump skipped by config]";
    }

    function contains(path, patterns) {
        for (var i = 0; i < patterns.length; i++)
            if (path.indexOf(patterns[i]) > -1) return true;
        return false;
    }

    function printStackTrace() {
        var th = Java.cast(CLS.Thread.currentThread(), CLS.Thread);
        var stack = th.getStackTrace(),
            e = null;

        for (var i = 0; i < stack.length; i++) {
            send("\t" + stack[i].getClassName() + "." + stack[i].getMethodName() + "(" + stack[i].getFileName() + ")");
        }
    }

    function isZero(block) {
        var m = /^[0\s]+$/.exec(block);
        return m != null && m.length > 0 && (m[0] == block);
    }

    function hexdump(buffer, blockSize) {
        blockSize = blockSize || 16;
        var lines = [];
        var hex = "0123456789ABCDEF";
        var prevZero = false,
            ctrZero = 0;
        for (var b = 0; b < buffer.length; b += blockSize) {
            var block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
            var addr = ("0000" + b.toString(16)).slice(-4);
            var codes = block.split('').map(function (ch) {
                var code = ch.charCodeAt(0);
                return " " + hex[(0xF0 & code) >> 4] + hex[0x0F & code];
            }).join("");
            codes += "   ".repeat(blockSize - block.length);
            var chars = block.replace(/[\\x00-\\x1F\\x20\n]/g, '.');
            chars += " ".repeat(blockSize - block.length);
            if (isZero(codes)) {
                ctrZero += blockSize;
                prevZero = true;
            } else {
                if (prevZero) {
                    lines.push("\t [" + ctrZero + "] bytes of zeroes");
                }
                lines.push(addr + " " + codes + "  " + chars);
                prevZero = false;
                ctrZero = 0;
            }
        }
        if (prevZero) {
            lines.push("\t [" + ctrZero + "] bytes of zeroes");
        }
        return lines.join("\\n");
    }

    function b2s(array) {
        var result = "";
        for (var i = 0; i < array.length; i++) {
            result += String.fromCharCode(modulus(array[i], 256));
        }
        return result;
    }

    function modulus(x, n) {
        return ((x % n) + n) % n;
    }

});