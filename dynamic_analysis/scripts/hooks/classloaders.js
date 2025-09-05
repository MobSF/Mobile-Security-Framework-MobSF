// 파일명: scripts/hooks/classloaders.js

// DEX 데이터를 Python으로 전송하는 헬퍼 함수
function sendDexData(metadata, dexBytes) {
    metadata.type = "DEX_DUMP";
    metadata.size = dexBytes.length;
    send(metadata, dexBytes);
    console.log(`[DEX Dump] ${metadata.source} - ${dexBytes.length} bytes sent.`);
}

function hook_classloaders() {
    // DexClassLoader 후킹
    const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function(dexPath, odexPath, libPath, parent) {
        console.log(`[Hook] DexClassLoader detected: ${dexPath}`);
        try {
            const path = Java.use("java.nio.file.Paths").get(dexPath, []);
            const dexBytes = Java.use("java.nio.file.Files").readAllBytes(path);
            const metadata = { source: "DexClassLoader", dex_path: dexPath };
            sendDexData(metadata, dexBytes);
        } catch (e) {
            console.error(`[!] DexClassLoader error: ${e}`);
        }
        return this.$init(dexPath, odexPath, libPath, parent);
    };

    // InMemoryDexClassLoader 후킹
    try {
        const InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(byteBuffer, loader) {
            console.log("[Hook] InMemoryDexClassLoader detected.");
            byteBuffer.rewind();
            const remaining = byteBuffer.remaining();
            const dexBytes = new Array(remaining);
            for(let i = 0; i < remaining; i++) {
                dexBytes[i] = byteBuffer.get(i);
            }
            const metadata = { source: "InMemoryDexClassLoader" };
            sendDexData(metadata, Java.array('byte', dexBytes));
            
            // 원본 메서드를 호출하기 전 버퍼 위치를 원래대로 되돌려야 합니다.
            byteBuffer.rewind(); 
            return this.$init(byteBuffer, loader);
        };
    } catch (e) {
        console.log("[i] InMemoryDexClassLoader not found on this Android version.");
    }

    // *** 추가된 부분: DexFile (openDexFile) 후킹 ***
    try {
        const DexFile = Java.use("dalvik.system.DexFile");
        
        // public DexFile(String dexPath, String odexPath, int flags) 생성자 후킹
        DexFile.$init.overload('java.lang.String', 'java.lang.String', 'int').implementation = function(dexPath, odexPath, flags) {
            console.log(`[Hook] DexFile.$init(String) detected: ${dexPath}`);
            try {
                // DexClassLoader와 동일한 방식으로 파일 읽고 덤프
                const path = Java.use("java.nio.file.Paths").get(dexPath, []);
                const dexBytes = Java.use("java.nio.file.Files").readAllBytes(path);
                const metadata = { source: "DexFile_init", dex_path: dexPath };
                sendDexData(metadata, dexBytes);
            } catch (e) {
                console.error(`[!] DexFile.$init error: ${e}`);
            }
            return this.$init(dexPath, odexPath, flags);
        };
    } catch (e) {
        console.log("[i] dalvik.system.DexFile not found.");
    }
}

// 모듈로 내보내기. require('./hooks/classloaders')를 통해 이 객체에 접근 가능.
module.exports = {
    hook: hook_classloaders
};