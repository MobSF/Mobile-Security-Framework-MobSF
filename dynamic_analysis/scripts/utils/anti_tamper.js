// 파일명: scripts/utils/anti_tamper.js

function bypass_all() {
    console.log("[Anti-Tamper] Bypassing reflection calls...");
    
    // 1. 자바 리플렉션 후킹
    const Method = Java.use('java.lang.reflect.Method');
    Method.invoke.implementation = function (obj, args) {
        const method_name = this.getName();
        // console.log(`[Reflection] Method.invoke called: ${method_name}`);
        return this.invoke(obj, args);
    };

    console.log("[Anti-Tamper] Bypassing native checks...");
    // 2. 네이티브 함수 후킹 (strstr로 'frida' 문자열 탐지 우회)
    Interceptor.attach(Module.findExportByName(null, "strstr"), {
        onEnter: function(args) {
            this.frida_detected = false;
            const haystack = args[0].readCString();
            const needle = args[1].readCString();
            if (haystack && needle && needle.includes("frida")) {
                this.frida_detected = true;
            }
        },
        onLeave: function(retval) {
            if (this.frida_detected) {
                console.log("[Anti-Tamper] 'frida' string detection bypassed in strstr!");
                retval.replace(0); // 'frida'를 찾지 못한 것처럼 0 (NULL)을 반환
            }
        }
    });
}

// 모듈로 내보내기. require('./utils/anti_tamper')를 통해 이 객체에 접근 가능.
module.exports = {
    bypass: bypass_all
};